#include "analysis/loganalysis/log_detector.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "analysis/loganalysis/log_manager.h"

namespace shieldtier {

namespace {

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}

std::string json_string(const json& obj, const std::string& key) {
    if (obj.contains(key) && obj[key].is_string()) {
        return obj[key].get<std::string>();
    }
    return "";
}

int64_t json_int64(const json& obj, const std::string& key) {
    if (obj.contains(key)) {
        if (obj[key].is_number()) return obj[key].get<int64_t>();
        if (obj[key].is_string()) {
            try { return std::stoll(obj[key].get<std::string>()); } catch (...) {}
        }
    }
    return 0;
}

bool is_internal_ip(const std::string& ip) {
    if (ip.empty()) return false;

    // Parse first two octets numerically to avoid 172.160.x.x false positive
    uint32_t octets[4] = {};
    int octet_count = 0;
    uint32_t current = 0;
    bool valid = true;

    for (size_t i = 0; i <= ip.size() && octet_count < 4; ++i) {
        if (i == ip.size() || ip[i] == '.') {
            if (current > 255) { valid = false; break; }
            octets[octet_count++] = current;
            current = 0;
        } else if (ip[i] >= '0' && ip[i] <= '9') {
            current = current * 10 + (ip[i] - '0');
        } else {
            valid = false;
            break;
        }
    }

    if (!valid || octet_count != 4) return false;

    // 10.0.0.0/8
    if (octets[0] == 10) return true;
    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) return true;
    // 192.168.0.0/16
    if (octets[0] == 192 && octets[1] == 168) return true;

    return false;
}

bool contains_word(const std::string& haystack, const std::string& word) {
    size_t pos = 0;
    while ((pos = haystack.find(word, pos)) != std::string::npos) {
        bool left_ok = (pos == 0 || !std::isalnum(static_cast<unsigned char>(haystack[pos - 1])));
        bool right_ok = (pos + word.size() >= haystack.size() ||
                         !std::isalnum(static_cast<unsigned char>(haystack[pos + word.size()])));
        if (left_ok && right_ok) return true;
        pos += word.size();
    }
    return false;
}

std::string truncate(const std::string& s, size_t max_len) {
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len) + "...";
}

// Helper: check if a lowered command matches two substrings (both must be present)
bool has_dual(const std::string& lower_cmd, const char* a, const char* b) {
    return lower_cmd.find(a) != std::string::npos &&
           lower_cmd.find(b) != std::string::npos;
}

}  // namespace

LogDetector::LogDetector() = default;

std::vector<Finding> LogDetector::detect(const std::vector<NormalizedEvent>& events) {
    std::vector<Finding> findings;

    auto bf = detect_brute_force(events);
    findings.insert(findings.end(), bf.begin(), bf.end());

    auto lm = detect_lateral_movement(events);
    findings.insert(findings.end(), lm.begin(), lm.end());

    auto pe = detect_privilege_escalation(events);
    findings.insert(findings.end(), pe.begin(), pe.end());

    auto de = detect_data_exfiltration(events);
    findings.insert(findings.end(), de.begin(), de.end());

    auto sc = detect_suspicious_commands(events);
    findings.insert(findings.end(), sc.begin(), sc.end());

    auto am = detect_account_manipulation(events);
    findings.insert(findings.end(), am.begin(), am.end());

    auto lc = detect_log_clearing(events);
    findings.insert(findings.end(), lc.begin(), lc.end());

    auto rdp = detect_rdp_abuse(events);
    findings.insert(findings.end(), rdp.begin(), rdp.end());

    return findings;
}

std::vector<Finding> LogDetector::detect_brute_force(
    const std::vector<NormalizedEvent>& events) {
    std::vector<Finding> findings;

    // Group failed auth events by source IP, tracking timestamps
    struct IpAttempts {
        int count = 0;
        int64_t first_ts = INT64_MAX;
        int64_t last_ts = 0;
    };
    std::unordered_map<std::string, IpAttempts> ip_failures;

    for (const auto& event : events) {
        std::string combined = to_lower(event.event_type + " " + event.message);
        bool is_failure = combined.find("fail") != std::string::npos &&
                          (combined.find("login") != std::string::npos ||
                           combined.find("auth") != std::string::npos ||
                           combined.find("password") != std::string::npos);

        if (!is_failure) continue;

        std::string src_ip = json_string(event.fields, "_src_ip");
        if (src_ip.empty()) src_ip = json_string(event.fields, "client_ip");
        if (src_ip.empty()) src_ip = event.source;
        if (src_ip.empty()) continue;

        auto& attempts = ip_failures[src_ip];
        attempts.count++;
        if (event.timestamp < attempts.first_ts) attempts.first_ts = event.timestamp;
        if (event.timestamp > attempts.last_ts) attempts.last_ts = event.timestamp;
    }

    for (const auto& [ip, attempts] : ip_failures) {
        int64_t window_ms = (attempts.last_ts > attempts.first_ts)
                                ? (attempts.last_ts - attempts.first_ts)
                                : 0;
        int64_t window_sec = window_ms / 1000;

        if (attempts.count >= 20 && window_sec <= 3600) {
            findings.push_back({
                "Log Detection: Password Spray Detected",
                "Source IP " + ip + " generated " + std::to_string(attempts.count) +
                    " failed authentication attempts — possible password spray attack",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"source_ip", ip},
                 {"attempt_count", attempts.count},
                 {"time_window_sec", window_sec},
                 {"mitre_technique", "T1110.003"}},
            });
        } else if (attempts.count >= 5 && window_sec <= 300) {
            findings.push_back({
                "Log Detection: Brute Force Login Attempts",
                "Source IP " + ip + " generated " + std::to_string(attempts.count) +
                    " failed authentication attempts within " +
                    std::to_string(window_sec) + " seconds",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"source_ip", ip},
                 {"attempt_count", attempts.count},
                 {"time_window_sec", window_sec},
                 {"mitre_technique", "T1110.001"}},
            });
        }
    }

    return findings;
}

std::vector<Finding> LogDetector::detect_lateral_movement(
    const std::vector<NormalizedEvent>& events) {
    std::vector<Finding> findings;

    // Track unique {src_ip -> set<dst_ip>} where dst_ip is internal
    std::unordered_map<std::string, std::unordered_set<std::string>> src_to_dsts;

    for (const auto& event : events) {
        std::string src_ip = json_string(event.fields, "_src_ip");
        if (src_ip.empty()) src_ip = json_string(event.fields, "client_ip");
        if (src_ip.empty()) continue;

        std::string dst_ip = json_string(event.fields, "_dst_ip");
        if (dst_ip.empty()) continue;

        if (is_internal_ip(dst_ip)) {
            src_to_dsts[src_ip].insert(dst_ip);
        }
    }

    for (const auto& [src_ip, dst_set] : src_to_dsts) {
        if (dst_set.size() < 3) continue;

        json dst_list = json::array();
        for (const auto& dst : dst_set) {
            dst_list.push_back(dst);
        }

        Severity sev = (dst_set.size() >= 5) ? Severity::kHigh : Severity::kMedium;
        findings.push_back({
            "Log Detection: Potential Lateral Movement",
            "Source IP " + src_ip + " connected to " +
                std::to_string(dst_set.size()) +
                " distinct internal destinations — possible lateral movement",
            sev,
            AnalysisEngine::kLogAnalysis,
            {{"source_ip", src_ip},
             {"destination_count", dst_set.size()},
             {"destination_ips", dst_list},
             {"mitre_technique", "T1021"}},
        });
    }

    return findings;
}

std::vector<Finding> LogDetector::detect_privilege_escalation(
    const std::vector<NormalizedEvent>& events) {
    std::vector<Finding> findings;

    static const struct {
        const char* pattern1;
        const char* pattern2;  // nullptr = single-pattern match
    } priv_patterns[] = {
        {"added to admin", nullptr},
        {"added to administrators", nullptr},
        {"group membership changed", nullptr},
        {"sedebugprivilege", nullptr},
        {"setcbprivilege", nullptr},
        {"seimpersonateprivilege", nullptr},
    };

    // Dual-pattern matches (both must be present)
    static const struct {
        const char* a;
        const char* b;
    } dual_patterns[] = {
        {"privilege", "escalat"},
        {"sudo", "root"},
        {"su ", "root"},
    };

    for (const auto& event : events) {
        std::string lower_msg = to_lower(event.message);

        for (const auto& pat : priv_patterns) {
            if (lower_msg.find(pat.pattern1) != std::string::npos) {
                std::string user = json_string(event.fields, "_user");
                findings.push_back({
                    "Log Detection: Privilege Escalation Indicator",
                    "Detected privilege escalation pattern: \"" +
                        std::string(pat.pattern1) + "\"",
                    Severity::kHigh,
                    AnalysisEngine::kLogAnalysis,
                    {{"user", user},
                     {"evidence", pat.pattern1},
                     {"mitre_technique", "T1078.003"}},
                });
                break;
            }
        }

        for (const auto& dp : dual_patterns) {
            if (lower_msg.find(dp.a) != std::string::npos &&
                lower_msg.find(dp.b) != std::string::npos) {
                std::string user = json_string(event.fields, "_user");
                findings.push_back({
                    "Log Detection: Privilege Escalation Indicator",
                    "Detected privilege escalation pattern: \"" +
                        std::string(dp.a) + "\" + \"" + std::string(dp.b) + "\"",
                    Severity::kHigh,
                    AnalysisEngine::kLogAnalysis,
                    {{"user", user},
                     {"evidence", std::string(dp.a) + " " + std::string(dp.b)},
                     {"mitre_technique", "T1078.003"}},
                });
                break;
            }
        }
    }

    return findings;
}

std::vector<Finding> LogDetector::detect_data_exfiltration(
    const std::vector<NormalizedEvent>& events) {
    std::vector<Finding> findings;

    constexpr int64_t kLargeTransferBytes = 100LL * 1024 * 1024;  // 100 MB

    // Track per-destination transfer counts for frequent small transfers
    std::unordered_map<std::string, int> dst_transfer_count;

    static const char* byte_fields[] = {
        "bytes_out", "BytesSent", "sc-bytes", "sentByte", "out_bytes"
    };

    for (const auto& event : events) {
        int64_t bytes_sent = 0;
        for (const char* field : byte_fields) {
            int64_t val = json_int64(event.fields, field);
            if (val > 0) {
                bytes_sent = val;
                break;
            }
        }

        std::string dst_ip = json_string(event.fields, "_dst_ip");

        // Large single transfer
        if (bytes_sent > kLargeTransferBytes) {
            findings.push_back({
                "Log Detection: Large Data Transfer",
                "Single transfer of " + std::to_string(bytes_sent / (1024 * 1024)) +
                    " MB detected" + (dst_ip.empty() ? "" : " to " + dst_ip),
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"destination_ip", dst_ip},
                 {"total_bytes", bytes_sent},
                 {"mitre_technique", "T1048"}},
            });
        }

        // Track frequent transfers per destination
        if (!dst_ip.empty() && bytes_sent > 0) {
            dst_transfer_count[dst_ip]++;
        }
    }

    // Check for frequent small transfers to the same destination
    for (const auto& [dst_ip, count] : dst_transfer_count) {
        if (count >= 50) {
            findings.push_back({
                "Log Detection: Frequent Data Transfers to Single Destination",
                "Detected " + std::to_string(count) +
                    " data transfer events to " + dst_ip +
                    " — possible staged exfiltration",
                Severity::kMedium,
                AnalysisEngine::kLogAnalysis,
                {{"destination_ip", dst_ip},
                 {"transfer_count", count},
                 {"mitre_technique", "T1048"}},
            });
        }
    }

    return findings;
}

std::vector<Finding> LogDetector::detect_suspicious_commands(
    const std::vector<NormalizedEvent>& events) {
    std::vector<Finding> findings;

    // Security tool names that attackers commonly kill
    static const char* security_tools[] = {
        "msmpeng", "mssense", "savservice", "avp", "avgnt", "bdagent",
        "ekrn", "mbam", "mcshield", "windefend", "carbonblack", "cb",
        "crowdstrike", "csfalcon", "cylance", "sentinelagent", "tanium",
    };

    for (const auto& event : events) {
        std::string cmd = json_string(event.fields, "_command");
        if (cmd.empty()) cmd = event.message;
        if (cmd.empty()) continue;

        std::string lower_cmd = to_lower(cmd);
        std::string user = json_string(event.fields, "_user");
        std::string cmd_truncated = truncate(cmd, 200);

        // ---------------------------------------------------------------
        // PowerShell encoded commands (T1059.001)
        // ---------------------------------------------------------------
        if (lower_cmd.find("powershell") != std::string::npos ||
            lower_cmd.find("pwsh") != std::string::npos) {
            if (lower_cmd.find("-enc") != std::string::npos ||
                lower_cmd.find("-encodedcommand") != std::string::npos ||
                lower_cmd.find("frombase64string") != std::string::npos) {
                findings.push_back({
                    "Log Detection: Encoded PowerShell Command",
                    "PowerShell executed with encoded command — commonly used to evade detection",
                    Severity::kHigh,
                    AnalysisEngine::kLogAnalysis,
                    {{"command", cmd_truncated},
                     {"user", user},
                     {"mitre_technique", "T1059.001"}},
                });
                continue;
            }
        }

        // ---------------------------------------------------------------
        // PowerShell download cradles (T1059.001)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "powershell", "downloadstring") ||
            has_dual(lower_cmd, "powershell", "downloadfile") ||
            has_dual(lower_cmd, "powershell", "downloaddata") ||
            has_dual(lower_cmd, "iex", "webclient") ||
            has_dual(lower_cmd, "invoke-expression", "webclient") ||
            has_dual(lower_cmd, "invoke-webrequest", "outfile") ||
            has_dual(lower_cmd, "start-bitstransfer", "http")) {
            findings.push_back({
                "Log Detection: PowerShell Download Cradle",
                "PowerShell download cradle detected — downloading and executing remote content",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1059.001"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // certutil decode/urlcache (T1140)
        // ---------------------------------------------------------------
        if (lower_cmd.find("certutil") != std::string::npos &&
            (lower_cmd.find("-decode") != std::string::npos ||
             lower_cmd.find("-urlcache") != std::string::npos)) {
            findings.push_back({
                "Log Detection: Certutil Abuse",
                "Certutil used for file decode or URL download — common LOLBin technique",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1140"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // bitsadmin transfer (T1197)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "bitsadmin", "/transfer")) {
            findings.push_back({
                "Log Detection: BITSAdmin File Transfer",
                "BITSAdmin used for file transfer — potential download of malicious payload",
                Severity::kMedium,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1197"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // MSHTA abuse (T1218.005)
        // ---------------------------------------------------------------
        if (lower_cmd.find("mshta") != std::string::npos &&
            (lower_cmd.find("javascript") != std::string::npos ||
             lower_cmd.find("vbscript") != std::string::npos ||
             lower_cmd.find("http") != std::string::npos)) {
            findings.push_back({
                "Log Detection: MSHTA Script Execution",
                "MSHTA executed with script content — LOLBin proxy execution technique",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1218.005"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Regsvr32 remote scriptlet (T1218.010)
        // ---------------------------------------------------------------
        if (lower_cmd.find("regsvr32") != std::string::npos &&
            (lower_cmd.find("/i:http") != std::string::npos ||
             has_dual(lower_cmd, "/s", "/n"))) {
            findings.push_back({
                "Log Detection: Regsvr32 Scriptlet Execution",
                "Regsvr32 invoked with remote scriptlet — Squiblydoo/Squiblytwo technique",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1218.010"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Rundll32 abuse (T1218.011)
        // ---------------------------------------------------------------
        if (lower_cmd.find("rundll32") != std::string::npos &&
            (lower_cmd.find("javascript") != std::string::npos ||
             lower_cmd.find("shell32") != std::string::npos ||
             lower_cmd.find("http") != std::string::npos)) {
            findings.push_back({
                "Log Detection: Rundll32 Abuse",
                "Rundll32 invoked with suspicious arguments — potential proxy execution",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1218.011"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // WMIC remote execution (T1047)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "wmic", "/node:")) {
            findings.push_back({
                "Log Detection: WMIC Remote Execution",
                "WMIC used with /node: parameter — remote process execution on another host",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1047"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Network share mounting (T1021.002)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "net use", "\\\\")) {
            findings.push_back({
                "Log Detection: Network Share Mounting",
                "Network share mounted via net use — potential lateral movement or data staging",
                Severity::kMedium,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1021.002"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Active Directory reconnaissance (T1482 / T1018)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "nltest", "/domain_trusts") ||
            lower_cmd.find("dsquery") != std::string::npos ||
            lower_cmd.find("ldapsearch") != std::string::npos) {
            findings.push_back({
                "Log Detection: Active Directory Reconnaissance",
                "AD/LDAP reconnaissance command detected — domain trust or object enumeration",
                Severity::kMedium,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1482"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Credential dumping tools (T1003)
        // ---------------------------------------------------------------
        if (lower_cmd.find("mimikatz") != std::string::npos ||
            lower_cmd.find("sekurlsa") != std::string::npos ||
            lower_cmd.find("kerberos::") != std::string::npos ||
            lower_cmd.find("lsadump::") != std::string::npos ||
            lower_cmd.find("invoke-mimikatz") != std::string::npos) {
            findings.push_back({
                "Log Detection: Credential Dumping Tool",
                "Credential dumping tool or module detected — Mimikatz or related tooling",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1003"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Lateral movement tools (T1570)
        // ---------------------------------------------------------------
        if (lower_cmd.find("psexec") != std::string::npos ||
            lower_cmd.find("wmiexec") != std::string::npos ||
            lower_cmd.find("smbexec") != std::string::npos ||
            lower_cmd.find("atexec") != std::string::npos ||
            lower_cmd.find("dcomexec") != std::string::npos) {
            findings.push_back({
                "Log Detection: Lateral Movement Tool",
                "Known lateral movement tool detected — remote execution framework",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1570"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Volume shadow copy deletion — ransomware (T1490)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "vssadmin", "delete shadows") ||
            has_dual(lower_cmd, "wmic", "shadowcopy delete")) {
            findings.push_back({
                "Log Detection: Volume Shadow Copy Deletion",
                "Shadow copies being deleted — critical ransomware indicator",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1490"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Boot config tampering — recovery disable (T1490)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "bcdedit", "/set") &&
            (lower_cmd.find("recoveryenabled no") != std::string::npos ||
             lower_cmd.find("bootstatuspolicy ignoreallfailures") != std::string::npos)) {
            findings.push_back({
                "Log Detection: Recovery Options Disabled",
                "Boot configuration modified to disable recovery — ransomware precursor",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1490"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Hidden file/directory attributes (T1564.001)
        // ---------------------------------------------------------------
        if (lower_cmd.find("attrib") != std::string::npos &&
            lower_cmd.find("+h") != std::string::npos &&
            lower_cmd.find("+s") != std::string::npos) {
            findings.push_back({
                "Log Detection: Hidden File Attribute Set",
                "File attributes set to hidden+system — attempt to conceal files on disk",
                Severity::kMedium,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1564.001"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Permission weakening via icacls (T1222.001)
        // ---------------------------------------------------------------
        if (lower_cmd.find("icacls") != std::string::npos &&
            lower_cmd.find("grant") != std::string::npos &&
            lower_cmd.find("everyone") != std::string::npos) {
            findings.push_back({
                "Log Detection: Permission Weakening",
                "File/directory permissions granted to Everyone — weakening access controls",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1222.001"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Firewall disable (T1562.004)
        // ---------------------------------------------------------------
        if ((lower_cmd.find("netsh") != std::string::npos &&
             lower_cmd.find("firewall") != std::string::npos &&
             lower_cmd.find("disable") != std::string::npos) ||
            (lower_cmd.find("netsh") != std::string::npos &&
             lower_cmd.find("advfirewall") != std::string::npos &&
             lower_cmd.find("off") != std::string::npos)) {
            findings.push_back({
                "Log Detection: Firewall Disabled",
                "Windows Firewall being disabled via netsh — defense evasion indicator",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1562.004"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Disable Windows Defender via registry (T1562.001)
        // ---------------------------------------------------------------
        if (lower_cmd.find("reg") != std::string::npos &&
            lower_cmd.find("add") != std::string::npos &&
            lower_cmd.find("disableantispyware") != std::string::npos) {
            findings.push_back({
                "Log Detection: Windows Defender Disabled via Registry",
                "Registry key set to disable Windows Defender — critical defense evasion",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1562.001"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Taskkill targeting security tools (T1562.001)
        // ---------------------------------------------------------------
        if (lower_cmd.find("taskkill") != std::string::npos &&
            lower_cmd.find("/f") != std::string::npos) {
            for (const char* tool : security_tools) {
                if (lower_cmd.find(tool) != std::string::npos) {
                    findings.push_back({
                        "Log Detection: Security Tool Terminated",
                        "Security tool process forcefully killed — defense evasion attempt",
                        Severity::kCritical,
                        AnalysisEngine::kLogAnalysis,
                        {{"command", cmd_truncated},
                         {"user", user},
                         {"killed_tool", tool},
                         {"mitre_technique", "T1562.001"}},
                    });
                    break;
                }
            }
            // Even if no tool matched, continue to check other patterns below
        }

        // ---------------------------------------------------------------
        // Privilege enumeration — whoami /priv (T1033)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "whoami", "/priv")) {
            findings.push_back({
                "Log Detection: Privilege Enumeration",
                "whoami /priv executed — enumerating current user privileges",
                Severity::kLow,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1033"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Credential enumeration — cmdkey /list (T1555.004)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "cmdkey", "/list")) {
            findings.push_back({
                "Log Detection: Stored Credential Enumeration",
                "cmdkey /list executed — enumerating stored Windows credentials",
                Severity::kMedium,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1555.004"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Kerberos ticket listing — klist (T1558)
        // ---------------------------------------------------------------
        if (contains_word(lower_cmd, "klist")) {
            findings.push_back({
                "Log Detection: Kerberos Ticket Enumeration",
                "klist executed — enumerating cached Kerberos tickets",
                Severity::kLow,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1558"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Event log clearing via wevtutil (T1070.001)
        // ---------------------------------------------------------------
        if (lower_cmd.find("wevtutil") != std::string::npos &&
            contains_word(lower_cmd, "cl")) {
            findings.push_back({
                "Log Detection: Event Log Clearing",
                "Windows event logs being cleared — critical indicator of anti-forensics",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1070.001"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Scheduled task creation (T1053.005)
        // ---------------------------------------------------------------
        if (has_dual(lower_cmd, "schtasks", "/create")) {
            findings.push_back({
                "Log Detection: Scheduled Task Creation",
                "Scheduled task created via command line — potential persistence mechanism",
                Severity::kMedium,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1053.005"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Service creation (T1543.003)
        // ---------------------------------------------------------------
        if (contains_word(lower_cmd, "sc") &&
            lower_cmd.find("create") != std::string::npos &&
            lower_cmd.find("binpath") != std::string::npos) {
            findings.push_back({
                "Log Detection: Service Creation",
                "New Windows service created via command line — potential persistence or privilege escalation",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1543.003"}},
            });
            continue;
        }

        // ---------------------------------------------------------------
        // Registry run key modification (T1547.001)
        // ---------------------------------------------------------------
        if (contains_word(lower_cmd, "reg") &&
            lower_cmd.find("add") != std::string::npos &&
            lower_cmd.find("run") != std::string::npos) {
            findings.push_back({
                "Log Detection: Registry Run Key Modification",
                "Registry Run key modified — common persistence mechanism for auto-start malware",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1547.001"}},
            });
            continue;
        }
    }

    return findings;
}

// ---------------------------------------------------------------------------
// Account manipulation detection (T1136 / T1098)
// ---------------------------------------------------------------------------
std::vector<Finding> LogDetector::detect_account_manipulation(
    const std::vector<NormalizedEvent>& events) {
    std::vector<Finding> findings;

    // Patterns: each entry is {needle1, needle2, description, severity, mitre}
    static const struct {
        const char* a;
        const char* b;
        const char* description;
        Severity severity;
        const char* mitre;
    } account_patterns[] = {
        {"net user", "/add",
         "Local user account created via net user /add",
         Severity::kHigh, "T1136.001"},
        {"net localgroup", "administrators /add",
         "User added to local Administrators group",
         Severity::kCritical, "T1098"},
        {"net group", "domain admins",
         "User added to Domain Admins group — critical privilege escalation",
         Severity::kCritical, "T1098"},
        {"add-localgroupmember", "administrators",
         "User added to local Administrators via PowerShell",
         Severity::kCritical, "T1098"},
        {"new-localuser", nullptr,
         "Local user account created via PowerShell New-LocalUser",
         Severity::kHigh, "T1136.001"},
    };

    for (const auto& event : events) {
        std::string cmd = json_string(event.fields, "_command");
        if (cmd.empty()) cmd = event.message;
        if (cmd.empty()) continue;

        std::string lower_cmd = to_lower(cmd);
        std::string user = json_string(event.fields, "_user");
        std::string cmd_truncated = truncate(cmd, 200);

        // Check event IDs for Windows Security log account events
        int64_t event_id = json_int64(event.fields, "_event_id");
        if (event_id == 0) event_id = json_int64(event.fields, "EventID");

        // Event ID 4720: A user account was created
        if (event_id == 4720) {
            findings.push_back({
                "Log Detection: User Account Created",
                "Windows Security event 4720 — a new user account was created",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"event_id", event_id},
                 {"user", user},
                 {"evidence", truncate(event.message, 200)},
                 {"mitre_technique", "T1136.001"}},
            });
            continue;
        }

        // Event ID 4728/4732/4756: Member added to security-enabled group
        if (event_id == 4728 || event_id == 4732 || event_id == 4756) {
            findings.push_back({
                "Log Detection: Group Membership Modified",
                "Windows Security event " + std::to_string(event_id) +
                    " — member added to security-enabled group",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"event_id", event_id},
                 {"user", user},
                 {"evidence", truncate(event.message, 200)},
                 {"mitre_technique", "T1098"}},
            });
            continue;
        }

        for (const auto& pat : account_patterns) {
            bool match = false;
            if (pat.b == nullptr) {
                match = lower_cmd.find(pat.a) != std::string::npos;
            } else {
                match = lower_cmd.find(pat.a) != std::string::npos &&
                        lower_cmd.find(pat.b) != std::string::npos;
            }
            if (match) {
                findings.push_back({
                    "Log Detection: Account Manipulation",
                    std::string(pat.description),
                    pat.severity,
                    AnalysisEngine::kLogAnalysis,
                    {{"command", cmd_truncated},
                     {"user", user},
                     {"mitre_technique", pat.mitre}},
                });
                break;
            }
        }
    }

    return findings;
}

// ---------------------------------------------------------------------------
// Log clearing detection (T1070.001)
// ---------------------------------------------------------------------------
std::vector<Finding> LogDetector::detect_log_clearing(
    const std::vector<NormalizedEvent>& events) {
    std::vector<Finding> findings;

    for (const auto& event : events) {
        std::string user = json_string(event.fields, "_user");

        // Check event IDs
        int64_t event_id = json_int64(event.fields, "_event_id");
        if (event_id == 0) event_id = json_int64(event.fields, "EventID");

        // Event ID 1102: The audit log was cleared
        if (event_id == 1102) {
            findings.push_back({
                "Log Detection: Audit Log Cleared",
                "Windows Security event 1102 — the audit log was cleared",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"event_id", event_id},
                 {"user", user},
                 {"evidence", truncate(event.message, 200)},
                 {"mitre_technique", "T1070.001"}},
            });
            continue;
        }

        // Event ID 104: System log cleared
        if (event_id == 104) {
            findings.push_back({
                "Log Detection: System Log Cleared",
                "Windows System event 104 — a system event log was cleared",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"event_id", event_id},
                 {"user", user},
                 {"evidence", truncate(event.message, 200)},
                 {"mitre_technique", "T1070.001"}},
            });
            continue;
        }

        // Check command-based log clearing
        std::string cmd = json_string(event.fields, "_command");
        if (cmd.empty()) cmd = event.message;
        if (cmd.empty()) continue;

        std::string lower_cmd = to_lower(cmd);
        std::string cmd_truncated = truncate(cmd, 200);

        // wevtutil cl (command-based clearing, also caught in suspicious_commands
        // but included here for completeness in the dedicated detector)
        if (lower_cmd.find("wevtutil") != std::string::npos &&
            contains_word(lower_cmd, "cl")) {
            findings.push_back({
                "Log Detection: Event Log Clearing via wevtutil",
                "Windows event logs cleared using wevtutil cl — anti-forensics",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1070.001"}},
            });
            continue;
        }

        // PowerShell Clear-EventLog
        if (lower_cmd.find("clear-eventlog") != std::string::npos) {
            findings.push_back({
                "Log Detection: Event Log Clearing via PowerShell",
                "Event log cleared using PowerShell Clear-EventLog cmdlet — anti-forensics",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1070.001"}},
            });
            continue;
        }

        // PowerShell Remove-EventLog
        if (lower_cmd.find("remove-eventlog") != std::string::npos) {
            findings.push_back({
                "Log Detection: Event Log Removal via PowerShell",
                "Event log removed using PowerShell Remove-EventLog cmdlet — anti-forensics",
                Severity::kCritical,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1070.001"}},
            });
            continue;
        }
    }

    return findings;
}

// ---------------------------------------------------------------------------
// RDP abuse detection (T1021.001)
// ---------------------------------------------------------------------------
std::vector<Finding> LogDetector::detect_rdp_abuse(
    const std::vector<NormalizedEvent>& events) {
    std::vector<Finding> findings;

    // Track RDP logon sources per target host: target -> set<source_ip>
    struct RdpInfo {
        std::unordered_set<std::string> source_ips;
        int64_t first_ts = INT64_MAX;
        int64_t last_ts = 0;
        int count = 0;
    };
    std::unordered_map<std::string, RdpInfo> rdp_by_target;

    for (const auto& event : events) {
        int64_t event_id = json_int64(event.fields, "_event_id");
        if (event_id == 0) event_id = json_int64(event.fields, "EventID");

        // Event ID 4624: successful logon
        if (event_id != 4624) continue;

        // Check for logon type 10 (RemoteInteractive / RDP)
        std::string logon_type = json_string(event.fields, "LogonType");
        if (logon_type.empty()) logon_type = json_string(event.fields, "_logon_type");
        int64_t logon_type_num = 0;
        if (!logon_type.empty()) {
            try { logon_type_num = std::stoll(logon_type); } catch (...) {}
        }
        if (logon_type_num == 0) {
            logon_type_num = json_int64(event.fields, "LogonType");
        }

        if (logon_type_num != 10) continue;

        // Extract source IP of the RDP session
        std::string src_ip = json_string(event.fields, "_src_ip");
        if (src_ip.empty()) src_ip = json_string(event.fields, "IpAddress");
        if (src_ip.empty()) src_ip = json_string(event.fields, "client_ip");
        if (src_ip.empty()) continue;

        // Target is the machine name or destination
        std::string target = json_string(event.fields, "_dst_ip");
        if (target.empty()) target = json_string(event.fields, "WorkstationName");
        if (target.empty()) target = event.source;
        if (target.empty()) target = "<unknown>";

        auto& info = rdp_by_target[target];
        info.source_ips.insert(src_ip);
        info.count++;
        if (event.timestamp < info.first_ts) info.first_ts = event.timestamp;
        if (event.timestamp > info.last_ts) info.last_ts = event.timestamp;
    }

    for (const auto& [target, info] : rdp_by_target) {
        // Multiple distinct source IPs connecting via RDP to same target
        if (info.source_ips.size() >= 3) {
            json src_list = json::array();
            for (const auto& ip : info.source_ips) {
                src_list.push_back(ip);
            }

            int64_t window_sec = (info.last_ts > info.first_ts)
                                     ? (info.last_ts - info.first_ts) / 1000
                                     : 0;

            findings.push_back({
                "Log Detection: Multiple RDP Sources to Single Host",
                "Host " + target + " received RDP connections from " +
                    std::to_string(info.source_ips.size()) +
                    " distinct source IPs — possible compromised jump box or lateral movement",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"target_host", target},
                 {"source_count", info.source_ips.size()},
                 {"source_ips", src_list},
                 {"total_rdp_logons", info.count},
                 {"time_window_sec", window_sec},
                 {"mitre_technique", "T1021.001"}},
            });
        }

        // High volume RDP logons (brute force success or automated lateral movement)
        if (info.count >= 10) {
            int64_t window_sec = (info.last_ts > info.first_ts)
                                     ? (info.last_ts - info.first_ts) / 1000
                                     : 0;

            findings.push_back({
                "Log Detection: High Volume RDP Logons",
                "Host " + target + " received " + std::to_string(info.count) +
                    " RDP logon events — possible automated lateral movement",
                (info.count >= 20) ? Severity::kCritical : Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"target_host", target},
                 {"logon_count", info.count},
                 {"time_window_sec", window_sec},
                 {"mitre_technique", "T1021.001"}},
            });
        }
    }

    return findings;
}

}  // namespace shieldtier
