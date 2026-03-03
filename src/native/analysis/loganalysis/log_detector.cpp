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

    for (const auto& event : events) {
        std::string cmd = json_string(event.fields, "_command");
        if (cmd.empty()) cmd = event.message;
        if (cmd.empty()) continue;

        std::string lower_cmd = to_lower(cmd);
        std::string user = json_string(event.fields, "_user");
        std::string cmd_truncated = truncate(cmd, 200);

        // PowerShell encoded commands
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

        // certutil decode/urlcache
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

        // bitsadmin transfer
        if (lower_cmd.find("bitsadmin") != std::string::npos &&
            lower_cmd.find("/transfer") != std::string::npos) {
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

        // LOLBins with suspicious arguments
        bool has_lolbin = lower_cmd.find("mshta") != std::string::npos ||
                          lower_cmd.find("rundll32") != std::string::npos ||
                          lower_cmd.find("regsvr32") != std::string::npos;
        bool has_lolbin_arg = lower_cmd.find("http") != std::string::npos ||
                              lower_cmd.find("javascript") != std::string::npos ||
                              lower_cmd.find("script") != std::string::npos;
        if (has_lolbin && has_lolbin_arg) {
            findings.push_back({
                "Log Detection: LOLBin Execution with Suspicious Arguments",
                "Living-off-the-land binary executed with script/URL arguments",
                Severity::kHigh,
                AnalysisEngine::kLogAnalysis,
                {{"command", cmd_truncated},
                 {"user", user},
                 {"mitre_technique", "T1218"}},
            });
            continue;
        }

        // Event log clearing
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

        // Scheduled task creation
        if (lower_cmd.find("schtasks") != std::string::npos &&
            lower_cmd.find("/create") != std::string::npos) {
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

        // Service creation
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

        // Registry run key modification
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

}  // namespace shieldtier
