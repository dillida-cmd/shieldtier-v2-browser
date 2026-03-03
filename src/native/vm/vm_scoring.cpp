#include "vm/vm_scoring.h"

#include <unordered_set>

namespace shieldtier {

namespace {

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string to_lower(const std::string& s) {
    std::string result = s;
    for (auto& c : result) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return result;
}

bool is_system_dir(const std::string& path) {
    auto lower = to_lower(path);
    return contains(lower, "\\windows\\") ||
           contains(lower, "\\system32\\") ||
           contains(lower, "\\syswow64\\") ||
           contains(lower, "/windows/") ||
           contains(lower, "/system32/") ||
           contains(lower, "/syswow64/");
}

bool is_executable_ext(const std::string& path) {
    auto lower = to_lower(path);
    auto len = lower.size();
    if (len < 4) return false;
    auto ext = lower.substr(len - 4);
    return ext == ".exe" || ext == ".dll" || ext == ".sys";
}

bool is_log_file(const std::string& path) {
    auto lower = to_lower(path);
    return contains(lower, ".log") || contains(lower, ".evtx") ||
           contains(lower, ".evt") || contains(lower, "\\logs\\") ||
           contains(lower, "/logs/");
}

bool is_suspicious_process(const std::string& name) {
    auto lower = to_lower(name);
    // Check substring — covers both exact match and full path
    return contains(lower, "cmd.exe") || contains(lower, "powershell.exe") ||
           contains(lower, "wscript.exe") || contains(lower, "cscript.exe") ||
           contains(lower, "mshta.exe") || contains(lower, "regsvr32.exe") ||
           contains(lower, "rundll32.exe");
}

bool ends_with(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool is_suspicious_tld(const std::string& domain) {
    auto lower = to_lower(domain);
    return ends_with(lower, ".tk") || ends_with(lower, ".ml") ||
           ends_with(lower, ".ga") || ends_with(lower, ".cf") ||
           ends_with(lower, ".xyz");
}

}  // namespace

Result<AnalysisEngineResult> VmScoring::score_vm_results(
    const std::vector<json>& events,
    const json& network_activity,
    double duration_ms) {
    auto event_findings = events_to_findings(events);
    auto net_findings = network_to_findings(network_activity);

    std::vector<Finding> all_findings;
    all_findings.reserve(event_findings.size() + net_findings.size());
    all_findings.insert(all_findings.end(),
                        std::make_move_iterator(event_findings.begin()),
                        std::make_move_iterator(event_findings.end()));
    all_findings.insert(all_findings.end(),
                        std::make_move_iterator(net_findings.begin()),
                        std::make_move_iterator(net_findings.end()));

    json raw_output;
    raw_output["event_count"] = events.size();
    raw_output["finding_count"] = all_findings.size();

    json net_summary;
    if (network_activity.contains("dns_queries")) {
        net_summary["dns_query_count"] = network_activity["dns_queries"].size();
    }
    if (network_activity.contains("http_requests")) {
        net_summary["http_request_count"] = network_activity["http_requests"].size();
    }
    if (network_activity.contains("connections")) {
        net_summary["connection_count"] = network_activity["connections"].size();
    }
    raw_output["network_summary"] = net_summary;

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kVmSandbox;
    result.success = true;
    result.findings = std::move(all_findings);
    result.raw_output = std::move(raw_output);
    result.duration_ms = duration_ms;

    return result;
}

std::vector<Finding> VmScoring::events_to_findings(
    const std::vector<json>& events) {
    std::vector<Finding> findings;

    for (const auto& event : events) {
        if (!event.is_object()) continue;

        auto category = event.value("category", "");
        auto action = event.value("action", "");
        auto detail = event.value("detail", "");
        auto path = event.value("path", "");

        if (category == "file") {
            if (action == "create" && is_system_dir(path)) {
                findings.push_back({
                    "File created in system directory",
                    "File written to protected system path: " + path,
                    Severity::kHigh,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1105"}, {"path", path}}
                });
            }
            if ((action == "modify" || action == "create") && is_executable_ext(path)) {
                findings.push_back({
                    "Executable file modified",
                    "Executable binary written or modified: " + path,
                    Severity::kMedium,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1574.001"}, {"path", path}}
                });
            }
            if (action == "delete" && is_log_file(path)) {
                findings.push_back({
                    "Log file deleted",
                    "Log or event file deleted (anti-forensics): " + path,
                    Severity::kHigh,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1070.004"}, {"path", path}}
                });
            }
        } else if (category == "registry") {
            auto key = event.value("key", "");
            auto key_lower = to_lower(key);

            if (contains(key_lower, "image file execution options")) {
                findings.push_back({
                    "IFEO debugger hijack",
                    "Image File Execution Options modification: " + key,
                    Severity::kCritical,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1546.012"}, {"key", key}}
                });
            } else if (contains(key_lower, "\\run") || contains(key_lower, "\\runonce")) {
                findings.push_back({
                    "Persistence via Run key",
                    "Registry Run/RunOnce key modified for persistence: " + key,
                    Severity::kHigh,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1547.001"}, {"key", key}}
                });
            } else if (contains(key_lower, "\\services\\")) {
                findings.push_back({
                    "Service installation",
                    "Registry Services key modified (service persistence): " + key,
                    Severity::kHigh,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1543.003"}, {"key", key}}
                });
            }
        } else if (category == "process") {
            if (action == "inject") {
                findings.push_back({
                    "Process injection detected",
                    "Process injection observed: " + detail,
                    Severity::kCritical,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1055"}, {"detail", detail}}
                });
            } else if (action == "privilege_escalation") {
                findings.push_back({
                    "Privilege escalation",
                    "Privilege escalation attempt detected: " + detail,
                    Severity::kCritical,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1068"}, {"detail", detail}}
                });
            } else if (action == "create") {
                auto process_name = event.value("name", "");
                if (process_name.empty()) process_name = detail;
                if (is_suspicious_process(process_name)) {
                    findings.push_back({
                        "Suspicious process spawned",
                        "Potentially malicious process created: " + process_name,
                        Severity::kHigh,
                        AnalysisEngine::kVmSandbox,
                        {{"mitre", "T1059"}, {"process", process_name}}
                    });
                }
            }
        } else if (category == "network") {
            if (action == "c2" || contains(to_lower(detail), "c2") ||
                contains(to_lower(detail), "command and control")) {
                findings.push_back({
                    "C2 communication detected",
                    "Command and control traffic observed: " + detail,
                    Severity::kHigh,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1071"}, {"detail", detail}}
                });
            }
            if (action == "dns_tunnel" || contains(to_lower(detail), "dns tunnel")) {
                findings.push_back({
                    "DNS tunneling detected",
                    "DNS tunneling activity observed: " + detail,
                    Severity::kHigh,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1071"}, {"detail", detail}}
                });
            }
            if (action == "exfiltration" || contains(to_lower(detail), "exfil")) {
                findings.push_back({
                    "Data exfiltration detected",
                    "Large outbound data transfer observed: " + detail,
                    Severity::kHigh,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1041"}, {"detail", detail}}
                });
            }

            // Unusual port detection
            auto port = event.value("port", 0);
            if (port > 0 && port != 80 && port != 443 && port != 53 &&
                port != 8080 && port != 8443) {
                auto dest = event.value("destination", "");
                findings.push_back({
                    "Connection on unusual port",
                    "Outbound connection to " + dest + ":" + std::to_string(port),
                    Severity::kMedium,
                    AnalysisEngine::kVmSandbox,
                    {{"mitre", "T1071"}, {"port", port}, {"destination", dest}}
                });
            }
        }
    }

    return findings;
}

std::vector<Finding> VmScoring::network_to_findings(const json& network_activity) {
    std::vector<Finding> findings;

    if (!network_activity.is_object()) return findings;

    // DNS analysis
    if (network_activity.contains("dns_queries") &&
        network_activity["dns_queries"].is_array()) {
        const auto& queries = network_activity["dns_queries"];
        int suspicious_tld_count = 0;
        std::unordered_set<std::string> unique_domains;

        for (const auto& query : queries) {
            auto domain = query.value("domain", "");
            if (domain.empty()) continue;

            unique_domains.insert(domain);

            if (is_suspicious_tld(domain)) {
                ++suspicious_tld_count;
                if (suspicious_tld_count <= 3) {
                    findings.push_back({
                        "DNS query to suspicious TLD",
                        "DNS resolution of domain with suspicious TLD: " + domain,
                        Severity::kMedium,
                        AnalysisEngine::kVmSandbox,
                        {{"mitre", "T1568"}, {"domain", domain}}
                    });
                }
            }
        }

        if (suspicious_tld_count > 3) {
            findings.push_back({
                "Multiple DNS queries to suspicious TLDs",
                std::to_string(suspicious_tld_count) + " queries to suspicious TLDs detected",
                Severity::kHigh,
                AnalysisEngine::kVmSandbox,
                {{"mitre", "T1568"}, {"count", suspicious_tld_count}}
            });
        }

        if (unique_domains.size() > 50) {
            findings.push_back({
                "Possible DGA activity",
                "High volume of unique DNS queries (" +
                    std::to_string(unique_domains.size()) +
                    " unique domains) suggests domain generation algorithm",
                Severity::kMedium,
                AnalysisEngine::kVmSandbox,
                {{"mitre", "T1568.002"},
                 {"unique_domain_count", unique_domains.size()}}
            });
        }
    }

    // HTTP analysis
    if (network_activity.contains("http_requests") &&
        network_activity["http_requests"].is_array()) {
        int post_count = 0;

        for (const auto& req : network_activity["http_requests"]) {
            auto method = to_lower(req.value("method", ""));
            if (method == "post") {
                ++post_count;
            }
        }

        if (post_count > 0) {
            findings.push_back({
                "Outbound HTTP POST",
                std::to_string(post_count) + " HTTP POST request(s) detected (potential data exfiltration)",
                Severity::kLow,
                AnalysisEngine::kVmSandbox,
                {{"mitre", "T1041"}, {"post_count", post_count}}
            });
        }
    }

    return findings;
}

}  // namespace shieldtier
