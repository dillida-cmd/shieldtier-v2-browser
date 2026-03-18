#include "analysis/loganalysis/log_analysis_engine.h"

#include <algorithm>
#include <set>

namespace shieldtier {

// ═════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════

std::string LogAnalysisEngine::meta_str(const json& fields, const char* key) {
    if (fields.is_null() || !fields.is_object()) return "";
    if (fields.contains(key) && fields[key].is_string()) return fields[key].get<std::string>();
    return "";
}

bool LogAnalysisEngine::ci_contains(const std::string& haystack, const std::string& needle) {
    if (needle.empty() || haystack.size() < needle.size()) return false;
    auto it = std::search(
        haystack.begin(), haystack.end(), needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}

std::string LogAnalysisEngine::to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

Severity LogAnalysisEngine::higher_sev(Severity a, Severity b) {
    return static_cast<int>(a) > static_cast<int>(b) ? a : b;
}

std::string LogAnalysisEngine::sev_str(Severity s) {
    switch (s) {
        case Severity::kCritical: return "critical";
        case Severity::kHigh: return "high";
        case Severity::kMedium: return "medium";
        case Severity::kLow: return "low";
        default: return "info";
    }
}

bool LogAnalysisEngine::is_noise_user(const std::string& user) {
    std::string u = to_lower(user);
    // Windows service accounts and well-known noise
    static const char* noise[] = {
        "system", "local service", "network service", "local system",
        "nt authority", "nt authority\\system", "nt authority\\local service",
        "nt authority\\network service", "nt service", "window manager",
        "font driver host", "dwm-1", "dwm-2", "dwm-3",
        "umfd-0", "umfd-1", "umfd-2", "umfd-3",
        "anonymous logon", "anonymous", "-", "n/a", "none", "",
        "defaultaccount", "guest", "wdagutilityaccount",
        // Common non-user values that leak through extraction
        "client", "package:", "upload", "deployment", "corporate",
    };
    for (const char* n : noise) {
        if (u == n) return true;
    }
    // Filter values with non-printable or binary garbage
    for (char c : user) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 32 && uc != '\t') return true;  // control chars
    }
    return false;
}

bool LogAnalysisEngine::is_valid_entity(const std::string& val) {
    if (val.empty() || val == "-" || val == "N/A" || val == "n/a") return false;
    if (val.size() > 200) return false;  // binary garbage
    // Must have at least 50% printable ASCII
    int printable = 0;
    for (char c : val) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= 32 && uc < 127) printable++;
    }
    if (val.size() > 3 && printable < (int)(val.size() * 0.5)) return false;
    return true;
}

bool LogAnalysisEngine::is_private_ip(const std::string& ip) {
    if (ip.substr(0, 3) == "10.") return true;
    if (ip.substr(0, 8) == "192.168.") return true;
    if (ip.substr(0, 4) == "172.") {
        auto dot = ip.find('.', 4);
        if (dot != std::string::npos) {
            int second = 0;
            try { second = std::stoi(ip.substr(4, dot - 4)); } catch (...) {}
            if (second >= 16 && second <= 31) return true;
        }
    }
    if (ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0") return true;
    return false;
}

std::string LogAnalysisEngine::mitre_for_finding(const std::string& title) {
    std::string t = to_lower(title);
    if (ci_contains(t, "brute") || ci_contains(t, "password spray"))     return "T1110";
    if (ci_contains(t, "encoded") && ci_contains(t, "powershell"))       return "T1059.001";
    if (ci_contains(t, "lolbin") || ci_contains(t, "certutil"))          return "T1218";
    if (ci_contains(t, "lateral") || ci_contains(t, "psexec"))           return "T1021";
    if (ci_contains(t, "privilege") || ci_contains(t, "escalat"))        return "T1078";
    if (ci_contains(t, "persistence") || ci_contains(t, "scheduled"))    return "T1053";
    if (ci_contains(t, "credential") || ci_contains(t, "mimikatz"))      return "T1003";
    if (ci_contains(t, "exfiltrat"))                                     return "T1041";
    if (ci_contains(t, "ransomware") || ci_contains(t, "encrypt"))       return "T1486";
    if (ci_contains(t, "log clear") || ci_contains(t, "audit"))          return "T1070.001";
    if (ci_contains(t, "webshell"))                                      return "T1505.003";
    if (ci_contains(t, "dns tunnel"))                                    return "T1071.004";
    if (ci_contains(t, "service") && ci_contains(t, "creat"))            return "T1543.003";
    if (ci_contains(t, "registry") || ci_contains(t, "run key"))         return "T1547.001";
    if (ci_contains(t, "port scan"))                                     return "T1046";
    return "";
}

std::string LogAnalysisEngine::kill_chain_phase(const std::string& mitre_id) {
    if (mitre_id.empty()) return "";
    // Map common MITRE IDs to kill chain phases
    if (mitre_id == "T1566" || mitre_id == "T1190" || mitre_id == "T1078") return "Initial Access";
    if (mitre_id.substr(0, 6) == "T1059." || mitre_id == "T1059" ||
        mitre_id == "T1204" || mitre_id == "T1106") return "Execution";
    if (mitre_id == "T1053" || mitre_id.substr(0, 6) == "T1053." ||
        mitre_id == "T1547" || mitre_id.substr(0, 6) == "T1547." ||
        mitre_id == "T1543" || mitre_id.substr(0, 6) == "T1543.") return "Persistence";
    if (mitre_id == "T1068" || mitre_id == "T1548") return "Privilege Escalation";
    if (mitre_id == "T1070" || mitre_id.substr(0, 6) == "T1070." ||
        mitre_id == "T1218" || mitre_id.substr(0, 6) == "T1218.") return "Defense Evasion";
    if (mitre_id == "T1003" || mitre_id.substr(0, 6) == "T1003." ||
        mitre_id == "T1110" || mitre_id.substr(0, 6) == "T1110.") return "Credential Access";
    if (mitre_id == "T1046" || mitre_id == "T1087" || mitre_id == "T1082") return "Discovery";
    if (mitre_id == "T1021" || mitre_id.substr(0, 6) == "T1021.") return "Lateral Movement";
    if (mitre_id == "T1074" || mitre_id.substr(0, 6) == "T1074.") return "Collection";
    if (mitre_id == "T1041" || mitre_id == "T1048") return "Exfiltration";
    if (mitre_id == "T1071" || mitre_id.substr(0, 6) == "T1071.") return "Command & Control";
    if (mitre_id == "T1486" || mitre_id == "T1489" || mitre_id == "T1490") return "Impact";
    if (mitre_id == "T1505" || mitre_id.substr(0, 6) == "T1505.") return "Persistence";
    return "";
}

// ═════════════════════════════════════════════════════════════════════
// Entity Extraction
// ═════════════════════════════════════════════════════════════════════

LogAnalysisEngine::EntityMaps
LogAnalysisEngine::extract_entities(const std::vector<NormalizedEvent>& events) {
    EntityMaps em;

    for (const auto& ev : events) {
        auto user = meta_str(ev.fields, "_user");
        auto src_ip = meta_str(ev.fields, "_src_ip");
        auto dst_ip = meta_str(ev.fields, "_dst_ip");
        auto host = meta_str(ev.fields, "_host");
        auto process = meta_str(ev.fields, "_process");
        auto command = meta_str(ev.fields, "_command");

        // Also try top-level source if no _host
        if (host.empty()) host = ev.source;

        // Also extract from message if metadata is sparse
        if (user.empty() && !ev.fields.is_null()) {
            user = meta_str(ev.fields, "user");
            if (user.empty()) user = meta_str(ev.fields, "User");
            if (user.empty()) user = meta_str(ev.fields, "Account Name");
        }

        // Track timestamp range
        std::string ts;
        if (!ev.fields.is_null() && ev.fields.contains("_raw_timestamp")) {
            ts = ev.fields["_raw_timestamp"].get<std::string>();
        }
        if (ts.empty() && ev.timestamp > 0) {
            ts = std::to_string(ev.timestamp);
        }
        if (!ts.empty()) {
            if (em.min_timestamp.empty() || ts < em.min_timestamp) em.min_timestamp = ts;
            if (em.max_timestamp.empty() || ts > em.max_timestamp) em.max_timestamp = ts;
        }

        if (!user.empty() && is_valid_entity(user) && !is_noise_user(user)) {
            em.users[user]++;
            em.user_max_sev[user] = higher_sev(em.user_max_sev[user], ev.severity);
        }
        if (!src_ip.empty()) {
            em.ips[src_ip]++;
            em.ip_max_sev[src_ip] = higher_sev(em.ip_max_sev[src_ip], ev.severity);
            if (!is_private_ip(src_ip)) em.external_ips[src_ip]++;
        }
        if (!dst_ip.empty()) {
            em.ips[dst_ip]++;
            em.ip_max_sev[dst_ip] = higher_sev(em.ip_max_sev[dst_ip], ev.severity);
            if (!is_private_ip(dst_ip)) em.external_ips[dst_ip]++;
        }
        if (!host.empty() && is_valid_entity(host)) {
            em.hosts[host]++;
            em.host_max_sev[host] = higher_sev(em.host_max_sev[host], ev.severity);
        }
        if (!process.empty() && is_valid_entity(process)) {
            em.processes[process]++;
            em.process_max_sev[process] = higher_sev(em.process_max_sev[process], ev.severity);
        }
        if (!command.empty() && is_valid_entity(command)) {
            em.commands[command]++;
        }
    }

    return em;
}

// ═════════════════════════════════════════════════════════════════════
// Top-level Analyze
// ═════════════════════════════════════════════════════════════════════

LogAnalysisEngine::Result
LogAnalysisEngine::analyze(const std::vector<NormalizedEvent>& events,
                           const std::vector<Finding>& findings) {
    auto em = extract_entities(events);

    Result result;
    result.hunting = build_hunting(events);
    result.insights = build_insights(em, events, findings);
    result.triage = build_triage(em, events, findings);
    result.investigation = build_investigation(events);
    result.graph = build_graph(em, events);
    result.verdict = build_verdict(events, findings, result.hunting);
    return result;
}

// ═════════════════════════════════════════════════════════════════════
// 1. INSIGHTS
// ═════════════════════════════════════════════════════════════════════

json LogAnalysisEngine::build_insights(const EntityMaps& em,
                                       const std::vector<NormalizedEvent>& events,
                                       const std::vector<Finding>& findings) {
    json insights = json::array();

    // Time range
    if (!em.min_timestamp.empty()) {
        insights.push_back({
            {"level", "info"},
            {"title", "Time Range"},
            {"detail", em.min_timestamp + " to " + em.max_timestamp +
                       " (" + std::to_string(events.size()) + " events)"}
        });
    }

    // Severity summary — count high/critical
    int high_crit = 0;
    std::string hc_types;
    std::unordered_map<std::string, int> hc_event_types;
    for (const auto& ev : events) {
        if (ev.severity == Severity::kHigh || ev.severity == Severity::kCritical) {
            high_crit++;
            if (!ev.event_type.empty()) hc_event_types[ev.event_type]++;
        }
    }
    if (high_crit > 0) {
        std::string detail = std::to_string(high_crit) + " high/critical events detected";
        if (!hc_event_types.empty()) {
            // Top 3 types
            std::vector<std::pair<std::string, int>> sorted_types(hc_event_types.begin(), hc_event_types.end());
            std::sort(sorted_types.begin(), sorted_types.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            detail += " — Types: ";
            int shown = 0;
            for (const auto& [type, count] : sorted_types) {
                if (shown++ > 0) detail += ", ";
                detail += type + " (" + std::to_string(count) + "x)";
                if (shown >= 3) break;
            }
        }
        insights.push_back({
            {"level", "danger"},
            {"title", std::to_string(high_crit) + " High/Critical Events"},
            {"detail", detail}
        });
    }

    // Findings summary
    if (!findings.empty()) {
        insights.push_back({
            {"level", findings.size() >= 3 ? "danger" : "warning"},
            {"title", std::to_string(findings.size()) + " Security Finding(s)"},
            {"detail", "Detection engine identified " + std::to_string(findings.size()) +
                       " potential security issues"}
        });
    }

    // Top users
    if (!em.users.empty()) {
        std::vector<std::pair<std::string, int>> sorted(em.users.begin(), em.users.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        std::string detail;
        int shown = 0;
        for (const auto& [user, count] : sorted) {
            if (shown++ > 0) detail += ", ";
            detail += user + " (" + std::to_string(count) + " events)";
            if (shown >= 5) break;
        }
        insights.push_back({
            {"level", "info"},
            {"title", std::to_string(em.users.size()) + " Unique User(s)"},
            {"detail", detail}
        });
    }

    // Top IPs
    if (!em.ips.empty()) {
        std::vector<std::pair<std::string, int>> sorted(em.ips.begin(), em.ips.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        std::string detail;
        int shown = 0;
        for (const auto& [ip, count] : sorted) {
            if (shown++ > 0) detail += ", ";
            detail += ip + " (" + std::to_string(count) + " events)";
            if (shown >= 5) break;
        }
        insights.push_back({
            {"level", em.external_ips.empty() ? "info" : "warning"},
            {"title", std::to_string(em.ips.size()) + " Unique IP(s)"},
            {"detail", detail}
        });
    }

    // External IPs
    if (!em.external_ips.empty()) {
        std::string detail;
        int shown = 0;
        std::vector<std::pair<std::string, int>> sorted(em.external_ips.begin(), em.external_ips.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        for (const auto& [ip, count] : sorted) {
            if (shown++ > 0) detail += ", ";
            detail += ip + " (" + std::to_string(count) + "x)";
            if (shown >= 10) break;
        }
        insights.push_back({
            {"level", "warning"},
            {"title", std::to_string(em.external_ips.size()) + " External IP(s)"},
            {"detail", detail}
        });
    }

    // Auth failure detection
    int auth_failures = 0;
    std::unordered_map<std::string, int> failure_ips;
    std::unordered_map<std::string, int> failure_users;
    for (const auto& ev : events) {
        std::string msg_lower = to_lower(ev.message);
        std::string etype = to_lower(ev.event_type);
        if (ci_contains(msg_lower, "fail") || ci_contains(msg_lower, "denied") ||
            ci_contains(etype, "fail") || ci_contains(etype, "denied") ||
            ci_contains(etype, "invalid")) {
            auth_failures++;
            auto ip = meta_str(ev.fields, "_src_ip");
            auto user = meta_str(ev.fields, "_user");
            if (!ip.empty()) failure_ips[ip]++;
            if (!user.empty()) failure_users[user]++;
        }
    }
    if (auth_failures >= 3) {
        std::string detail = std::to_string(auth_failures) + " failed attempts";
        if (!failure_users.empty()) {
            detail += " | Users: ";
            int shown = 0;
            std::vector<std::pair<std::string, int>> sorted(failure_users.begin(), failure_users.end());
            std::sort(sorted.begin(), sorted.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            for (const auto& [u, c] : sorted) {
                if (shown++ > 0) detail += ", ";
                detail += u + " (" + std::to_string(c) + "x)";
                if (shown >= 3) break;
            }
        }
        if (!failure_ips.empty()) {
            detail += " | IPs: ";
            int shown = 0;
            std::vector<std::pair<std::string, int>> sorted(failure_ips.begin(), failure_ips.end());
            std::sort(sorted.begin(), sorted.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            for (const auto& [ip, c] : sorted) {
                if (shown++ > 0) detail += ", ";
                detail += ip + " (" + std::to_string(c) + "x)";
                if (shown >= 3) break;
            }
        }
        bool is_brute = false;
        for (const auto& [ip, c] : failure_ips) {
            if (c >= 5) { is_brute = true; break; }
        }
        insights.push_back({
            {"level", is_brute ? "danger" : "warning"},
            {"title", is_brute ? "Possible Brute Force" : "Authentication Failures"},
            {"detail", detail}
        });
    }

    return insights;
}

// ═════════════════════════════════════════════════════════════════════
// 2. TRIAGE
// ═════════════════════════════════════════════════════════════════════

json LogAnalysisEngine::build_triage(const EntityMaps& em,
                                     const std::vector<NormalizedEvent>& events,
                                     const std::vector<Finding>& findings) {
    // Incident score from findings
    int score = 0;
    for (const auto& f : findings) {
        score += (f.severity == Severity::kCritical) ? 25 :
                 (f.severity == Severity::kHigh) ? 15 :
                 (f.severity == Severity::kMedium) ? 8 :
                 (f.severity == Severity::kLow) ? 3 : 0;
    }
    // Also bump score for high-severity events even without findings
    for (const auto& ev : events) {
        if (ev.severity == Severity::kCritical) score += 5;
        else if (ev.severity == Severity::kHigh) score += 2;
    }
    if (score > 100) score = 100;

    Severity inc_sev = (score >= 75) ? Severity::kCritical :
                       (score >= 50) ? Severity::kHigh :
                       (score >= 25) ? Severity::kMedium :
                       (score >= 10) ? Severity::kLow : Severity::kInfo;

    // Helper lambda to build entity array
    auto build_entity_arr = [](const std::unordered_map<std::string, int>& counts,
                                const std::unordered_map<std::string, Severity>& max_sevs,
                                int limit = 20) -> json {
        std::vector<std::pair<std::string, int>> sorted(counts.begin(), counts.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        json arr = json::array();
        int shown = 0;
        for (const auto& [val, count] : sorted) {
            if (shown++ >= limit) break;
            Severity sev = Severity::kInfo;
            auto it = max_sevs.find(val);
            if (it != max_sevs.end()) sev = it->second;
            arr.push_back({
                {"value", val},
                {"count", count},
                {"severity", sev_str(sev)},
                {"context", "Seen in " + std::to_string(count) + " events"}
            });
        }
        return arr;
    };

    // Build command entities from the commands map (no severity tracking for commands)
    std::unordered_map<std::string, Severity> cmd_sev;  // empty, use info
    json commands_arr = json::array();
    {
        std::vector<std::pair<std::string, int>> sorted(em.commands.begin(), em.commands.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        int shown = 0;
        for (const auto& [val, count] : sorted) {
            if (shown++ >= 20) break;
            // Detect suspicious commands
            Severity sev = Severity::kInfo;
            std::string lower = to_lower(val);
            if (ci_contains(lower, "mimikatz") || ci_contains(lower, "procdump") ||
                ci_contains(lower, "-enc") || ci_contains(lower, "invoke-")) {
                sev = Severity::kHigh;
            } else if (ci_contains(lower, "net user") || ci_contains(lower, "whoami") ||
                       ci_contains(lower, "tasklist")) {
                sev = Severity::kMedium;
            }
            commands_arr.push_back({
                {"value", val.substr(0, 200)},
                {"count", count},
                {"severity", sev_str(sev)},
                {"context", "Executed " + std::to_string(count) + " time(s)"}
            });
        }
    }

    // External IPs
    std::unordered_map<std::string, Severity> ext_ip_sev;
    for (const auto& [ip, _] : em.external_ips) {
        auto it = em.ip_max_sev.find(ip);
        ext_ip_sev[ip] = (it != em.ip_max_sev.end()) ? it->second : Severity::kLow;
    }

    // Attack chain from findings MITRE mappings
    json attack_chain = json::array();
    std::unordered_map<std::string, std::pair<int, std::vector<std::string>>> phase_data; // phase -> (count, indicators)
    for (const auto& f : findings) {
        std::string mitre = f.metadata.value("mitre_technique", "");
        if (mitre.empty()) mitre = mitre_for_finding(f.title);
        if (!mitre.empty()) {
            std::string phase = kill_chain_phase(mitre);
            if (!phase.empty()) {
                phase_data[phase].first++;
                phase_data[phase].second.push_back(f.title);
            }
        }
    }
    // Also scan events for attack indicators
    for (const auto& ev : events) {
        if (ev.severity >= Severity::kHigh) {
            std::string etype = to_lower(ev.event_type);
            if (ci_contains(etype, "auth") || ci_contains(etype, "login") || ci_contains(etype, "logon")) {
                phase_data["Initial Access"].first++;
            }
            if (ci_contains(etype, "exec") || ci_contains(etype, "process") || ci_contains(etype, "spawn")) {
                phase_data["Execution"].first++;
            }
        }
    }
    // Convert to array
    static const char* kPhaseOrder[] = {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command & Control", "Exfiltration", "Impact"
    };
    for (const char* phase : kPhaseOrder) {
        auto it = phase_data.find(phase);
        if (it != phase_data.end()) {
            json indicators = json::array();
            for (const auto& ind : it->second.second) indicators.push_back(ind);
            attack_chain.push_back({
                {"phase", phase},
                {"events", it->second.first},
                {"indicators", indicators}
            });
        }
    }

    return {
        {"incident", {{"severity", sev_str(inc_sev)}, {"score", score}}},
        {"entities", {
            {"users", build_entity_arr(em.users, em.user_max_sev)},
            {"ips", build_entity_arr(em.ips, em.ip_max_sev)},
            {"hosts", build_entity_arr(em.hosts, em.host_max_sev)},
            {"processes", build_entity_arr(em.processes, em.process_max_sev)},
            {"commands", commands_arr},
            {"externalIps", build_entity_arr(em.external_ips, ext_ip_sev)},
        }},
        {"attackChain", attack_chain},
    };
}

// ═════════════════════════════════════════════════════════════════════
// 3. INVESTIGATION
// ═════════════════════════════════════════════════════════════════════

json LogAnalysisEngine::build_investigation(const std::vector<NormalizedEvent>& events) {
    json chains = json::array();

    // Helper to build event JSON
    auto ev_json = [this](const NormalizedEvent& ev) -> json {
        std::string ts;
        if (!ev.fields.is_null() && ev.fields.contains("_raw_timestamp")) {
            ts = ev.fields["_raw_timestamp"].get<std::string>();
        }
        if (ts.empty() && ev.timestamp > 0) ts = std::to_string(ev.timestamp);
        return {
            {"timestamp", ts},
            {"source", ev.source},
            {"eventType", ev.event_type},
            {"severity", sev_str(ev.severity)},
            {"category", ev.event_type.empty() ? ev.source : ev.event_type},
            {"message", ev.message},
            {"raw", ev.message},
            {"metadata", ev.fields.is_null() ? json::object() : ev.fields},
        };
    };

    // ── Authentication chains: group failures/successes by user ──
    std::unordered_map<std::string, std::vector<size_t>> auth_by_user;
    for (size_t i = 0; i < events.size(); ++i) {
        std::string msg_lower = to_lower(events[i].message);
        std::string etype = to_lower(events[i].event_type);
        bool is_auth = ci_contains(msg_lower, "auth") || ci_contains(msg_lower, "login") ||
                       ci_contains(msg_lower, "logon") || ci_contains(msg_lower, "password") ||
                       ci_contains(msg_lower, "ssh") || ci_contains(msg_lower, "credential") ||
                       ci_contains(etype, "auth") || ci_contains(etype, "login") ||
                       ci_contains(etype, "logon") || ci_contains(etype, "signin") ||
                       ci_contains(etype, "fail") || ci_contains(etype, "success");
        if (is_auth) {
            std::string user = meta_str(events[i].fields, "_user");
            if (user.empty()) user = meta_str(events[i].fields, "user");
            if (user.empty()) user = "unknown";
            auth_by_user[user].push_back(i);
        }
    }
    for (const auto& [user, indices] : auth_by_user) {
        if (indices.size() < 2) continue;
        Severity max_sev = Severity::kInfo;
        json chain_events = json::array();
        for (size_t idx : indices) {
            if (chain_events.size() >= 50) break;
            chain_events.push_back(ev_json(events[idx]));
            max_sev = higher_sev(max_sev, events[idx].severity);
        }
        chains.push_back({
            {"type", "authentication"},
            {"title", "Authentication activity for " + user},
            {"events", chain_events},
            {"severity", sev_str(max_sev)},
        });
    }

    // ── Process chains: group by (host, parent process) ──
    std::unordered_map<std::string, std::vector<size_t>> proc_by_host;
    for (size_t i = 0; i < events.size(); ++i) {
        std::string proc = meta_str(events[i].fields, "_process");
        if (proc.empty()) continue;
        std::string etype = to_lower(events[i].event_type);
        bool is_proc = ci_contains(etype, "process") || ci_contains(etype, "exec") ||
                       ci_contains(etype, "spawn") || ci_contains(etype, "create") ||
                       !meta_str(events[i].fields, "_command").empty();
        if (!is_proc) continue;
        std::string host = meta_str(events[i].fields, "_host");
        if (host.empty()) host = events[i].source;
        std::string key = host + "|" + proc;
        proc_by_host[key].push_back(i);
    }
    for (const auto& [key, indices] : proc_by_host) {
        if (indices.size() < 2) continue;
        auto sep = key.find('|');
        std::string host = key.substr(0, sep);
        std::string proc = key.substr(sep + 1);
        Severity max_sev = Severity::kInfo;
        json chain_events = json::array();
        for (size_t idx : indices) {
            if (chain_events.size() >= 50) break;
            chain_events.push_back(ev_json(events[idx]));
            max_sev = higher_sev(max_sev, events[idx].severity);
        }
        chains.push_back({
            {"type", "process"},
            {"title", proc + " on " + host},
            {"events", chain_events},
            {"severity", sev_str(max_sev)},
        });
    }

    // ── Network chains: group by (src_ip → dst_ip) ──
    std::unordered_map<std::string, std::vector<size_t>> net_by_pair;
    for (size_t i = 0; i < events.size(); ++i) {
        std::string src = meta_str(events[i].fields, "_src_ip");
        std::string dst = meta_str(events[i].fields, "_dst_ip");
        if (src.empty() || dst.empty()) continue;
        std::string etype = to_lower(events[i].event_type);
        bool is_net = ci_contains(etype, "connect") || ci_contains(etype, "network") ||
                      ci_contains(etype, "flow") || ci_contains(etype, "dns") ||
                      ci_contains(etype, "firewall") || !dst.empty();
        if (!is_net) continue;
        net_by_pair[src + "→" + dst].push_back(i);
    }
    for (const auto& [pair, indices] : net_by_pair) {
        if (indices.size() < 2) continue;
        auto arrow = pair.find("→");
        std::string src = pair.substr(0, arrow);
        std::string dst = pair.substr(arrow + 3);  // UTF-8 arrow is 3 bytes
        Severity max_sev = Severity::kInfo;
        json chain_events = json::array();
        for (size_t idx : indices) {
            if (chain_events.size() >= 50) break;
            chain_events.push_back(ev_json(events[idx]));
            max_sev = higher_sev(max_sev, events[idx].severity);
        }
        chains.push_back({
            {"type", "network"},
            {"title", src + " → " + dst + " (" + std::to_string(indices.size()) + " connections)"},
            {"events", chain_events},
            {"severity", sev_str(max_sev)},
        });
    }

    // ── File access chains: events with file paths grouped by host ──
    std::unordered_map<std::string, std::vector<size_t>> file_by_host;
    for (size_t i = 0; i < events.size(); ++i) {
        std::string etype = to_lower(events[i].event_type);
        std::string msg = to_lower(events[i].message);
        bool is_file = ci_contains(etype, "file") || ci_contains(etype, "write") ||
                       ci_contains(etype, "read") || ci_contains(etype, "delete") ||
                       ci_contains(etype, "create") || ci_contains(etype, "modify") ||
                       ci_contains(msg, "file_created") || ci_contains(msg, "file_modified");
        if (!is_file) continue;
        std::string host = meta_str(events[i].fields, "_host");
        if (host.empty()) host = events[i].source;
        if (host.empty()) host = "unknown";
        file_by_host[host].push_back(i);
    }
    for (const auto& [host, indices] : file_by_host) {
        if (indices.size() < 2) continue;
        Severity max_sev = Severity::kInfo;
        json chain_events = json::array();
        for (size_t idx : indices) {
            if (chain_events.size() >= 50) break;
            chain_events.push_back(ev_json(events[idx]));
            max_sev = higher_sev(max_sev, events[idx].severity);
        }
        chains.push_back({
            {"type", "file_access"},
            {"title", "File activity on " + host},
            {"events", chain_events},
            {"severity", sev_str(max_sev)},
        });
    }

    // Sort chains: highest severity first, then by event count
    std::sort(chains.begin(), chains.end(), [](const json& a, const json& b) {
        static const std::unordered_map<std::string, int> sev_order = {
            {"critical", 0}, {"high", 1}, {"medium", 2}, {"low", 3}, {"info", 4}
        };
        int sa = 4, sb = 4;
        auto it_a = sev_order.find(a.value("severity", "info"));
        auto it_b = sev_order.find(b.value("severity", "info"));
        if (it_a != sev_order.end()) sa = it_a->second;
        if (it_b != sev_order.end()) sb = it_b->second;
        if (sa != sb) return sa < sb;
        return a["events"].size() > b["events"].size();
    });

    // Cap total chains
    if (chains.size() > 50) chains = json(std::vector<json>(chains.begin(), chains.begin() + 50));

    return {{"chains", chains}};
}

// ═════════════════════════════════════════════════════════════════════
// 4. GRAPH
// ═════════════════════════════════════════════════════════════════════

json LogAnalysisEngine::build_graph(const EntityMaps& em,
                                    const std::vector<NormalizedEvent>& events) {
    json nodes = json::array();
    json edges_arr = json::array();
    std::set<std::string> node_ids;

    // Helper to add a node if not already present
    auto ensure_node = [&](const std::string& id, const std::string& type,
                           const std::string& label, Severity sev, int count) {
        if (node_ids.count(id)) return;
        node_ids.insert(id);
        nodes.push_back({
            {"id", id}, {"type", type}, {"label", label},
            {"severity", sev_str(sev)}, {"eventCount", count},
        });
    };

    // Track edges for dedup: key = "source|target|label" -> count
    std::unordered_map<std::string, int> edge_counts;
    std::unordered_map<std::string, Severity> edge_sev;

    auto add_edge = [&](const std::string& src, const std::string& tgt,
                        const std::string& label, Severity sev) {
        std::string key = src + "|" + tgt + "|" + label;
        edge_counts[key]++;
        edge_sev[key] = higher_sev(edge_sev[key], sev);
    };

    // Add top entities as nodes (cap each type)
    auto add_top_nodes = [&](const std::unordered_map<std::string, int>& counts,
                             const std::unordered_map<std::string, Severity>& sevs,
                             const std::string& type, int limit) {
        std::vector<std::pair<std::string, int>> sorted(counts.begin(), counts.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        int n = 0;
        for (const auto& [val, count] : sorted) {
            if (n++ >= limit) break;
            Severity sev = Severity::kInfo;
            auto it = sevs.find(val);
            if (it != sevs.end()) sev = it->second;
            ensure_node(type + ":" + val, type, val, sev, count);
        }
    };

    add_top_nodes(em.users, em.user_max_sev, "user", 20);
    add_top_nodes(em.hosts, em.host_max_sev, "host", 15);
    add_top_nodes(em.processes, em.process_max_sev, "process", 20);
    add_top_nodes(em.ips, em.ip_max_sev, "ip", 20);

    // Scan events to build edges
    for (const auto& ev : events) {
        std::string user = meta_str(ev.fields, "_user");
        std::string src_ip = meta_str(ev.fields, "_src_ip");
        std::string dst_ip = meta_str(ev.fields, "_dst_ip");
        std::string host = meta_str(ev.fields, "_host");
        if (host.empty()) host = ev.source;
        std::string proc = meta_str(ev.fields, "_process");

        // user → host (authenticated_on)
        if (!user.empty() && !host.empty() &&
            node_ids.count("user:" + user) && node_ids.count("host:" + host)) {
            add_edge("user:" + user, "host:" + host, "on", ev.severity);
        }

        // user → ip (authenticated_from)
        if (!user.empty() && !src_ip.empty() &&
            node_ids.count("user:" + user) && node_ids.count("ip:" + src_ip)) {
            add_edge("ip:" + src_ip, "user:" + user, "auth", ev.severity);
        }

        // user → process (ran)
        if (!user.empty() && !proc.empty() &&
            node_ids.count("user:" + user) && node_ids.count("process:" + proc)) {
            add_edge("user:" + user, "process:" + proc, "ran", ev.severity);
        }

        // process → host (ran_on)
        if (!proc.empty() && !host.empty() &&
            node_ids.count("process:" + proc) && node_ids.count("host:" + host)) {
            add_edge("process:" + proc, "host:" + host, "ran_on", ev.severity);
        }

        // ip → ip (connected_to)
        if (!src_ip.empty() && !dst_ip.empty() && src_ip != dst_ip &&
            node_ids.count("ip:" + src_ip) && node_ids.count("ip:" + dst_ip)) {
            add_edge("ip:" + src_ip, "ip:" + dst_ip, "connected", ev.severity);
        }

        // process → dst_ip (connected_to)
        if (!proc.empty() && !dst_ip.empty() &&
            node_ids.count("process:" + proc) && node_ids.count("ip:" + dst_ip)) {
            add_edge("process:" + proc, "ip:" + dst_ip, "connected", ev.severity);
        }
    }

    // Convert edge map to array
    for (const auto& [key, count] : edge_counts) {
        auto sep1 = key.find('|');
        auto sep2 = key.find('|', sep1 + 1);
        edges_arr.push_back({
            {"source", key.substr(0, sep1)},
            {"target", key.substr(sep1 + 1, sep2 - sep1 - 1)},
            {"label", key.substr(sep2 + 1)},
            {"count", count},
            {"severity", sev_str(edge_sev[key])},
        });
    }

    return {{"nodes", nodes}, {"edges", edges_arr}};
}

// ═════════════════════════════════════════════════════════════════════
// 5. VERDICT
// ═════════════════════════════════════════════════════════════════════

json LogAnalysisEngine::build_verdict(const std::vector<NormalizedEvent>& events,
                                      const std::vector<Finding>& findings,
                                      const json& hunting_results) {
    int score = 0;
    json signals = json::array();
    std::set<std::string> kill_chain_phases;

    // Score from findings
    for (const auto& f : findings) {
        int pts = (f.severity == Severity::kCritical) ? 25 :
                  (f.severity == Severity::kHigh) ? 15 :
                  (f.severity == Severity::kMedium) ? 8 :
                  (f.severity == Severity::kLow) ? 3 : 0;
        score += pts;

        std::string mitre = f.metadata.value("mitre_technique", "");
        if (mitre.empty()) mitre = mitre_for_finding(f.title);
        std::string phase = kill_chain_phase(mitre);
        if (!phase.empty()) kill_chain_phases.insert(phase);

        json signal = {
            {"title", f.title},
            {"severity", sev_str(f.severity)},
            {"evidence", f.description},
        };
        if (!mitre.empty()) signal["mitre"] = mitre;
        signals.push_back(signal);
    }

    // Score from hunting results
    if (hunting_results.is_array()) {
        for (const auto& hr : hunting_results) {
            int mc = hr.value("matchCount", 0);
            if (mc == 0) continue;
            std::string sev = hr.contains("query") ? hr["query"].value("severity", "low") : "low";
            int pts = (sev == "critical") ? 20 : (sev == "high") ? 12 :
                      (sev == "medium") ? 6 : 2;
            score += std::min(pts * mc, pts * 3);  // Cap per query

            if (hr.contains("query")) {
                std::string mitre = hr["query"].value("mitre", "");
                std::string phase = kill_chain_phase(mitre);
                if (!phase.empty()) kill_chain_phases.insert(phase);

                signals.push_back({
                    {"title", hr["query"].value("name", "Hunting match")},
                    {"severity", sev},
                    {"evidence", std::to_string(mc) + " match(es): " + hr["query"].value("description", "")},
                    {"mitre", mitre},
                });
            }
        }
    }

    // Score from high-severity events (if no findings/hunting)
    if (findings.empty() && (!hunting_results.is_array() || hunting_results.empty())) {
        for (const auto& ev : events) {
            if (ev.severity == Severity::kCritical) score += 3;
            else if (ev.severity == Severity::kHigh) score += 1;
        }
    }

    if (score > 100) score = 100;

    std::string verdict_str = (score >= 75) ? "critical" :
                              (score >= 50) ? "compromised" :
                              (score >= 20) ? "suspicious" : "clean";

    int confidence = std::min(score, 95);

    // Kill chain array
    json kc_arr = json::array();
    for (const char* phase : {"Initial Access", "Execution", "Persistence",
         "Privilege Escalation", "Defense Evasion", "Credential Access",
         "Discovery", "Lateral Movement", "Collection",
         "Command & Control", "Exfiltration", "Impact"}) {
        if (kill_chain_phases.count(phase)) kc_arr.push_back(phase);
    }

    std::string reasoning = "Analyzed " + std::to_string(events.size()) + " events";
    if (!findings.empty()) {
        reasoning += ", found " + std::to_string(findings.size()) + " security findings";
    }
    if (!kill_chain_phases.empty()) {
        reasoning += " across " + std::to_string(kill_chain_phases.size()) + " kill chain phases";
    }

    return {
        {"verdict", verdict_str},
        {"confidence", confidence},
        {"signals", signals},
        {"falsePositives", json::array()},
        {"killChain", kc_arr},
        {"reasoning", reasoning},
    };
}

// ═════════════════════════════════════════════════════════════════════
// 6. HUNTING
// ═════════════════════════════════════════════════════════════════════

json LogAnalysisEngine::build_hunting(const std::vector<NormalizedEvent>& events) {
    json results = json::array();

    auto ev_json = [this](const NormalizedEvent& ev) -> json {
        std::string ts;
        if (!ev.fields.is_null() && ev.fields.contains("_raw_timestamp")) {
            ts = ev.fields["_raw_timestamp"].get<std::string>();
        }
        if (ts.empty() && ev.timestamp > 0) ts = std::to_string(ev.timestamp);
        return {
            {"timestamp", ts}, {"source", ev.source}, {"eventType", ev.event_type},
            {"severity", sev_str(ev.severity)},
            {"category", ev.event_type.empty() ? ev.source : ev.event_type},
            {"message", ev.message}, {"raw", ev.message},
            {"metadata", ev.fields.is_null() ? json::object() : ev.fields},
        };
    };

    auto add_result = [&](const char* id, const char* name, const char* desc,
                          const char* mitre, const char* cat, const char* sev,
                          json& matches) {
        if (matches.empty()) return;
        results.push_back({
            {"query", {{"id", id}, {"name", name}, {"description", desc},
                       {"mitre", mitre}, {"category", cat}, {"severity", sev},
                       {"source", "ShieldTier"}}},
            {"matches", matches},
            {"matchCount", static_cast<int>(matches.size())},
        });
    };

    // ═══════════════════════════════════════════════════════════════
    // Phase 1: Index events for aggregate detection
    // ═══════════════════════════════════════════════════════════════

    // Auth failure tracking: ip → event indices
    std::unordered_map<std::string, std::vector<size_t>> auth_fail_by_ip;
    // Invalid user tracking: ip → set of usernames
    std::unordered_map<std::string, std::set<std::string>> invalid_users_by_ip;
    // Successful logins: ip → event indices
    std::unordered_map<std::string, std::vector<size_t>> auth_success_by_ip;
    // Sudo failures: user → event indices
    std::unordered_map<std::string, std::vector<size_t>> sudo_fail_by_user;
    // Session opens: user → event indices
    std::unordered_map<std::string, std::vector<size_t>> session_open_by_user;
    // Preauth disconnects: ip → count
    std::unordered_map<std::string, int> preauth_by_ip;
    // Group membership changes: event indices
    std::vector<size_t> group_change_events;
    // Account management: event indices
    std::vector<size_t> account_mgmt_events;
    // Network connections by dst IP: dst_ip → set of ports
    std::unordered_map<std::string, std::set<std::string>> ports_by_dst;
    // DNS queries by domain: domain → count
    std::unordered_map<std::string, int> dns_query_counts;

    for (size_t i = 0; i < events.size(); ++i) {
        const auto& ev = events[i];
        std::string msg_lower = to_lower(ev.message);
        std::string etype = to_lower(ev.event_type);
        std::string ip = meta_str(ev.fields, "_src_ip");
        std::string user = meta_str(ev.fields, "_user");
        if (user.empty()) user = meta_str(ev.fields, "user");
        std::string cmd = to_lower(meta_str(ev.fields, "_command"));
        std::string proc = to_lower(meta_str(ev.fields, "_process"));
        int event_id = 0;
        if (!ev.fields.is_null() && ev.fields.contains("event_id") && ev.fields["event_id"].is_number()) {
            event_id = ev.fields["event_id"].get<int>();
        }

        // ── Classify events ──

        // Auth failures: Failed password, login_failure, EventID 4625, PAM failure
        bool is_auth_fail = ci_contains(etype, "login_failure") || ci_contains(etype, "failed_login") ||
            ci_contains(etype, "pam_auth_failure") || event_id == 4625 ||
            (ci_contains(msg_lower, "failed password") || ci_contains(msg_lower, "authentication failure")) ||
            (ci_contains(msg_lower, "fail") && (ci_contains(msg_lower, "login") || ci_contains(msg_lower, "auth") ||
             ci_contains(msg_lower, "password") || ci_contains(msg_lower, "logon")));
        if (is_auth_fail && !ip.empty()) auth_fail_by_ip[ip].push_back(i);

        // Invalid user attempts
        bool is_invalid_user = ci_contains(msg_lower, "invalid user") || ci_contains(etype, "invalid_user");
        if (is_invalid_user && !ip.empty() && !user.empty()) invalid_users_by_ip[ip].insert(user);

        // Auth successes: Accepted, login_success, EventID 4624
        bool is_auth_success = ci_contains(etype, "login_success") || ci_contains(etype, "accepted_login") ||
            event_id == 4624 || ci_contains(msg_lower, "accepted password") ||
            ci_contains(msg_lower, "accepted publickey") ||
            (ci_contains(msg_lower, "success") && (ci_contains(msg_lower, "logon") || ci_contains(msg_lower, "login")));
        if (is_auth_success && !ip.empty()) auth_success_by_ip[ip].push_back(i);

        // Sudo failures
        bool is_sudo_fail = ci_contains(etype, "sudo_failure") ||
            (ci_contains(msg_lower, "sudo") && ci_contains(msg_lower, "authentication failure"));
        if (is_sudo_fail && !user.empty()) sudo_fail_by_user[user].push_back(i);

        // Session opens (especially root)
        bool is_session_open = ci_contains(etype, "session_opened") ||
            (ci_contains(msg_lower, "session opened") && ci_contains(msg_lower, "user"));
        if (is_session_open && !user.empty()) session_open_by_user[user].push_back(i);

        // Preauth disconnects (SSH scanner probes)
        if (ci_contains(msg_lower, "preauth") || ci_contains(msg_lower, "[preauth]") ||
            ci_contains(etype, "preauth_disconnect")) {
            if (!ip.empty()) preauth_by_ip[ip]++;
        }

        // Group membership changes: EventID 4732, 4733, member_added, member_removed
        if (event_id == 4732 || event_id == 4733 || ci_contains(etype, "member_added") ||
            ci_contains(etype, "member_removed") || ci_contains(msg_lower, "added to group") ||
            ci_contains(msg_lower, "removed from group")) {
            group_change_events.push_back(i);
        }

        // Account management: create/delete/enable/disable/password reset
        if (event_id == 4720 || event_id == 4722 || event_id == 4724 || event_id == 4725 ||
            event_id == 4726 || ci_contains(etype, "account_created") ||
            ci_contains(etype, "account_deleted") || ci_contains(etype, "account_enabled") ||
            ci_contains(etype, "account_disabled") || ci_contains(etype, "password_reset")) {
            account_mgmt_events.push_back(i);
        }

        // Port tracking for scan detection
        std::string dst_ip = meta_str(ev.fields, "_dst_ip");
        std::string dst_port = meta_str(ev.fields, "_dst_port");
        if (!dst_ip.empty() && !dst_port.empty()) ports_by_dst[dst_ip].insert(dst_port);

        // DNS tracking
        if (ci_contains(etype, "dns") || event_id == 22) {
            std::string query = meta_str(ev.fields, "QueryName");
            if (query.empty()) query = meta_str(ev.fields, "query");
            if (!query.empty()) {
                // Extract base domain (last 2 parts)
                auto parts_end = query.rfind('.');
                if (parts_end != std::string::npos) {
                    auto parts_start = query.rfind('.', parts_end - 1);
                    std::string base = (parts_start != std::string::npos) ? query.substr(parts_start + 1) : query;
                    dns_query_counts[base]++;
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 2: Aggregate MITRE ATT&CK detections
    // ═══════════════════════════════════════════════════════════════

    // ── T1110: Brute Force (aggregate: 5+ failures per IP) ──
    {
        json matches = json::array();
        for (const auto& [ip, indices] : auth_fail_by_ip) {
            if (indices.size() >= 5) {
                std::set<std::string> users;
                for (size_t idx : indices) {
                    std::string u = meta_str(events[idx].fields, "_user");
                    if (!u.empty()) users.insert(u);
                }
                std::string user_list;
                for (const auto& u : users) {
                    if (!user_list.empty()) user_list += ", ";
                    user_list += u;
                }
                std::string evidence = "Brute force from " + ip + ": " +
                    std::to_string(indices.size()) + " failed attempts";
                if (!user_list.empty()) evidence += " targeting: " + user_list;
                if (matches.size() < 20) {
                    matches.push_back({{"event", ev_json(events[indices[0]])}, {"evidence", evidence}});
                }
            }
        }
        const char* sev = "high";
        for (const auto& [ip, indices] : auth_fail_by_ip) {
            if (indices.size() >= 20) { sev = "critical"; break; }
        }
        add_result("T1110", "Brute Force Attack",
            "Multiple authentication failures from same source IP detected",
            "T1110", "credential_access", sev, matches);
    }

    // ── T1110.003: Password Spraying (many IPs, same user pattern) ──
    {
        json matches = json::array();
        for (const auto& [ip, users] : invalid_users_by_ip) {
            if (users.size() >= 3) {
                std::string user_list;
                int shown = 0;
                for (const auto& u : users) {
                    if (shown++ > 0) user_list += ", ";
                    user_list += u;
                    if (shown >= 10) { user_list += "..."; break; }
                }
                std::string evidence = "User enumeration from " + ip + ": " +
                    std::to_string(users.size()) + " invalid usernames — " + user_list;
                if (matches.size() < 20) {
                    // Find first event for this IP
                    for (size_t i = 0; i < events.size() && matches.size() < 20; ++i) {
                        if (meta_str(events[i].fields, "_src_ip") == ip &&
                            ci_contains(to_lower(events[i].message), "invalid user")) {
                            matches.push_back({{"event", ev_json(events[i])}, {"evidence", evidence}});
                            break;
                        }
                    }
                }
            }
        }
        add_result("T1110.003", "User Enumeration / Password Spray",
            "Multiple unique invalid usernames attempted from same source",
            "T1110.003", "credential_access", "high", matches);
    }

    // ── T1078: Successful Login from Attacker IP (CRITICAL) ──
    {
        json matches = json::array();
        std::set<std::string> attacker_ips;
        for (const auto& [ip, indices] : auth_fail_by_ip) {
            if (indices.size() >= 5) attacker_ips.insert(ip);
        }
        for (const auto& [ip, indices] : auth_success_by_ip) {
            if (attacker_ips.count(ip)) {
                for (size_t idx : indices) {
                    std::string user = meta_str(events[idx].fields, "_user");
                    std::string evidence = "CRITICAL: Successful login by '" + user +
                        "' from attacker IP " + ip + " (previously " +
                        std::to_string(auth_fail_by_ip[ip].size()) + " failed attempts)";
                    if (matches.size() < 20) {
                        matches.push_back({{"event", ev_json(events[idx])}, {"evidence", evidence}});
                    }
                }
            }
        }
        add_result("T1078", "Valid Account Compromise",
            "Successful login detected from IP that was previously brute-forcing — possible compromise",
            "T1078", "initial_access", "critical", matches);
    }

    // ── T1548: Privilege Escalation (sudo failures + root sessions) ──
    {
        json matches = json::array();
        for (const auto& [user, indices] : sudo_fail_by_user) {
            if (indices.size() >= 3) {
                std::string evidence = "Privilege escalation attempt: " +
                    std::to_string(indices.size()) + " sudo failures for user '" + user + "'";
                if (matches.size() < 20) {
                    matches.push_back({{"event", ev_json(events[indices[0]])}, {"evidence", evidence}});
                }
            }
        }
        // Root session opens
        auto root_it = session_open_by_user.find("root");
        if (root_it != session_open_by_user.end() && !root_it->second.empty()) {
            std::string evidence = "Root session opened " +
                std::to_string(root_it->second.size()) + " time(s) — verify authorization";
            if (matches.size() < 20) {
                matches.push_back({{"event", ev_json(events[root_it->second[0]])}, {"evidence", evidence}});
            }
        }
        add_result("T1548", "Privilege Escalation",
            "Repeated sudo failures or root session activity detected",
            "T1548", "privilege_escalation", "high", matches);
    }

    // ── T1046: Network Scanning (SSH probes + port scanning) ──
    {
        json matches = json::array();
        for (const auto& [ip, count] : preauth_by_ip) {
            if (count >= 10) {
                std::string evidence = "SSH scanning from " + ip + ": " +
                    std::to_string(count) + " preauth disconnects";
                for (size_t i = 0; i < events.size() && matches.size() < 20; ++i) {
                    if (meta_str(events[i].fields, "_src_ip") == ip &&
                        ci_contains(to_lower(events[i].message), "preauth")) {
                        matches.push_back({{"event", ev_json(events[i])}, {"evidence", evidence}});
                        break;
                    }
                }
            }
        }
        for (const auto& [dst, ports] : ports_by_dst) {
            if (ports.size() >= 15) {
                std::string evidence = "Port scan targeting " + dst + ": " +
                    std::to_string(ports.size()) + " unique ports probed";
                if (matches.size() < 20) {
                    for (size_t i = 0; i < events.size(); ++i) {
                        if (meta_str(events[i].fields, "_dst_ip") == dst) {
                            matches.push_back({{"event", ev_json(events[i])}, {"evidence", evidence}});
                            break;
                        }
                    }
                }
            }
        }
        add_result("T1046", "Network Service Scanning",
            "SSH scanner probes or port scanning activity detected",
            "T1046", "discovery", "medium", matches);
    }

    // ── T1098: Account Manipulation (group changes, account mgmt) ──
    {
        json matches = json::array();
        for (size_t idx : group_change_events) {
            std::string user = meta_str(events[idx].fields, "_user");
            std::string evidence = "Group membership change: " + events[idx].message.substr(0, 150);
            if (matches.size() < 20) {
                matches.push_back({{"event", ev_json(events[idx])}, {"evidence", evidence}});
            }
        }
        for (size_t idx : account_mgmt_events) {
            std::string evidence = "Account management: " + events[idx].message.substr(0, 150);
            if (matches.size() < 20) {
                matches.push_back({{"event", ev_json(events[idx])}, {"evidence", evidence}});
            }
        }
        add_result("T1098", "Account Manipulation",
            "User account or group membership modifications detected",
            "T1098", "persistence", matches.empty() ? "medium" : "high", matches);
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 3: Per-event MITRE pattern matching (message + metadata)
    // ═══════════════════════════════════════════════════════════════

    // Each entry: id, name, desc, mitre, category, severity, match_fn
    struct PatternQuery {
        const char* id; const char* name; const char* desc;
        const char* mitre; const char* cat; const char* sev;
    };

    static const PatternQuery pqueries[] = {
        {"T1059.001", "PowerShell Execution", "Encoded/obfuscated PowerShell commands",
         "T1059.001", "execution", "high"},
        {"T1218", "LOLBin Abuse", "Living-off-the-land binary misuse for defense evasion",
         "T1218", "defense_evasion", "high"},
        {"T1003", "Credential Dumping", "LSASS access, mimikatz, credential harvesting",
         "T1003", "credential_access", "critical"},
        {"T1021", "Lateral Movement", "PsExec, WinRM, network logon type 3/10",
         "T1021", "lateral_movement", "high"},
        {"T1071.004", "DNS Tunneling", "Unusually long DNS queries or TXT record abuse",
         "T1071.004", "command_control", "medium"},
        {"T1486", "Ransomware", "Encrypted file extensions, shadow copy deletion, ransom notes",
         "T1486", "impact", "critical"},
        {"T1070.001", "Log Clearing", "Event log clearing or audit policy tampering",
         "T1070.001", "defense_evasion", "high"},
        {"T1053.005", "Scheduled Task", "Scheduled task creation for persistence",
         "T1053.005", "persistence", "medium"},
        {"T1543.003", "Service Creation", "New service installed with suspicious binary path",
         "T1543.003", "persistence", "medium"},
        {"T1547.001", "Registry Run Keys", "Run/RunOnce registry modification for persistence",
         "T1547.001", "persistence", "medium"},
        {"T1505.003", "Web Shell", "Shell process spawned by web server",
         "T1505.003", "persistence", "critical"},
        {"T1074", "Data Staging", "Archive creation with password or in temp directories",
         "T1074", "collection", "medium"},
        {"T1562.001", "Disable Security Tools", "Tamper protection disable, AV exclusion, firewall off",
         "T1562.001", "defense_evasion", "high"},
        {"T1105", "Remote File Download", "Downloading tools via curl/wget/certutil/bitsadmin",
         "T1105", "command_control", "high"},
        {"T1027", "Obfuscated Files", "Base64 encoding, XOR, script obfuscation",
         "T1027", "defense_evasion", "medium"},
        {"T1036", "Masquerading", "Process name mimicking system binaries from wrong path",
         "T1036", "defense_evasion", "medium"},
        {"T1055", "Process Injection", "Remote thread creation, memory allocation in other process",
         "T1055", "defense_evasion", "high"},
        {"T1082", "System Discovery", "systeminfo, hostname, whoami, ipconfig enumeration",
         "T1082", "discovery", "low"},
        {"T1087", "Account Discovery", "net user, net group, wmic useraccount enumeration",
         "T1087", "discovery", "low"},
        {"T1018", "Remote System Discovery", "net view, ping sweep, arp -a, nslookup",
         "T1018", "discovery", "low"},
        {"T1049", "Network Connection Discovery", "netstat, ss, net session, established connections",
         "T1049", "discovery", "low"},
        {"T1057", "Process Discovery", "tasklist, ps, wmic process, get-process enumeration",
         "T1057", "discovery", "low"},
        {"T1102", "Audit Log Cleared (EventID 1102)", "Windows Security audit log was cleared",
         "T1070.001", "defense_evasion", "critical"},
        {"T1136", "Account Creation", "New local or domain account created",
         "T1136", "persistence", "medium"},
    };

    for (const auto& pq : pqueries) {
        json matches = json::array();
        std::string qid(pq.id);

        for (const auto& ev : events) {
            std::string msg = to_lower(ev.message);
            std::string cmd = to_lower(meta_str(ev.fields, "_command"));
            std::string proc = to_lower(meta_str(ev.fields, "_process"));
            std::string parent = to_lower(meta_str(ev.fields, "_parent_process"));
            std::string etype = to_lower(ev.event_type);
            int eid = 0;
            if (!ev.fields.is_null() && ev.fields.contains("event_id") && ev.fields["event_id"].is_number())
                eid = ev.fields["event_id"].get<int>();
            std::string evidence;

            if (qid == "T1059.001") {
                if ((ci_contains(cmd, "-enc") || ci_contains(cmd, "-encodedcommand") ||
                     ci_contains(cmd, "frombase64string") || ci_contains(cmd, "invoke-expression") ||
                     ci_contains(cmd, "iex(") || ci_contains(cmd, "invoke-webrequest") ||
                     ci_contains(cmd, "downloadstring") || ci_contains(cmd, "downloadfile") ||
                     ci_contains(cmd, "invoke-mimikatz") || ci_contains(cmd, "invoke-shellcode") ||
                     ci_contains(cmd, "new-object net.webclient")) &&
                    (ci_contains(proc, "powershell") || ci_contains(cmd, "powershell") || ci_contains(cmd, "pwsh")))
                    evidence = "PowerShell: " + (cmd.empty() ? msg : cmd).substr(0, 200);
            }
            else if (qid == "T1218") {
                if ((ci_contains(proc, "certutil") && (ci_contains(cmd, "-urlcache") || ci_contains(cmd, "-decode") || ci_contains(cmd, "-encode"))) ||
                    (ci_contains(proc, "mshta") && (ci_contains(cmd, "javascript") || ci_contains(cmd, "vbscript") || ci_contains(cmd, "http"))) ||
                    (ci_contains(proc, "rundll32") && (ci_contains(cmd, "javascript") || ci_contains(cmd, "shell32") || ci_contains(cmd, "advpack"))) ||
                    (ci_contains(proc, "regsvr32") && (ci_contains(cmd, "/s") || ci_contains(cmd, "scrobj") || ci_contains(cmd, "http"))) ||
                    (ci_contains(proc, "bitsadmin") && (ci_contains(cmd, "/transfer") || ci_contains(cmd, "/create"))) ||
                    (ci_contains(proc, "wmic") && (ci_contains(cmd, "process call create") || ci_contains(cmd, "/node:"))) ||
                    (ci_contains(proc, "msiexec") && (ci_contains(cmd, "/q") || ci_contains(cmd, "http"))) ||
                    (ci_contains(proc, "cmstp") && ci_contains(cmd, "/s")))
                    evidence = "LOLBin: " + proc + " " + cmd.substr(0, 150);
            }
            else if (qid == "T1003") {
                if (ci_contains(cmd, "mimikatz") || ci_contains(cmd, "sekurlsa") ||
                    ci_contains(cmd, "procdump") || ci_contains(cmd, "comsvcs.dll") ||
                    ci_contains(cmd, "ntdsutil") || ci_contains(cmd, "ntds.dit") ||
                    ci_contains(cmd, "sam") && ci_contains(cmd, "save") ||
                    ci_contains(proc, "mimikatz") || ci_contains(msg, "lsass") ||
                    ci_contains(cmd, "kerberoast") || ci_contains(cmd, "rubeus") ||
                    ci_contains(cmd, "invoke-kerberoast") || ci_contains(cmd, "asreproast") ||
                    (eid == 10 && ci_contains(msg, "lsass")))
                    evidence = "Credential access: " + (cmd.empty() ? msg : cmd).substr(0, 200);
            }
            else if (qid == "T1021") {
                if (ci_contains(cmd, "psexec") || ci_contains(proc, "psexec") ||
                    ci_contains(cmd, "winrm") || ci_contains(cmd, "invoke-command") ||
                    ci_contains(cmd, "enter-pssession") || ci_contains(cmd, "wmiexec") ||
                    ci_contains(cmd, "smbexec") || ci_contains(cmd, "atexec") ||
                    ci_contains(msg, "logon type:") && (ci_contains(msg, "3") || ci_contains(msg, "10")) ||
                    eid == 4624 && ci_contains(msg, "logon type"))
                    evidence = "Lateral movement: " + msg.substr(0, 200);
            }
            else if (qid == "T1071.004") {
                std::string query = meta_str(ev.fields, "QueryName");
                if (query.empty()) query = meta_str(ev.fields, "query");
                if (!query.empty()) {
                    auto dot = query.find('.');
                    if (dot != std::string::npos && dot > 40)
                        evidence = "DNS tunnel: long subdomain (" + std::to_string(dot) + " chars) " + query.substr(0, 80);
                }
                if (evidence.empty() && (ci_contains(msg, "type:txt") || ci_contains(msg, "type:16") || ci_contains(msg, "type:null")))
                    evidence = "DNS suspicious query: " + msg.substr(0, 150);
            }
            else if (qid == "T1486") {
                if (ci_contains(msg, ".encrypted") || ci_contains(msg, ".locked") || ci_contains(msg, ".crypto") ||
                    ci_contains(msg, ".locky") || ci_contains(msg, ".ryuk") || ci_contains(msg, ".conti") ||
                    ci_contains(msg, ".lockbit") || ci_contains(msg, ".blackcat") || ci_contains(msg, ".hive") ||
                    ci_contains(msg, "ransom") || ci_contains(msg, "how_to_decrypt") || ci_contains(msg, "restore_files") ||
                    (ci_contains(cmd, "vssadmin") && ci_contains(cmd, "delete shadows")) ||
                    (ci_contains(cmd, "bcdedit") && ci_contains(cmd, "recoveryenabled")) ||
                    (ci_contains(cmd, "wbadmin") && ci_contains(cmd, "delete")))
                    evidence = "Ransomware: " + (cmd.empty() ? msg : cmd).substr(0, 200);
            }
            else if (qid == "T1070.001") {
                if ((ci_contains(cmd, "wevtutil") && ci_contains(cmd, "cl")) ||
                    ci_contains(cmd, "clear-eventlog") || ci_contains(cmd, "remove-eventlog") ||
                    eid == 1102 || ci_contains(etype, "log_cleared") || ci_contains(etype, "audit_log_cleared") ||
                    ci_contains(msg, "audit log was cleared") || ci_contains(msg, "event log was cleared") ||
                    (ci_contains(cmd, "auditpol") && ci_contains(cmd, "/clear")))
                    evidence = "Log clearing: " + (cmd.empty() ? msg : cmd).substr(0, 200);
            }
            else if (qid == "T1053.005") {
                if ((ci_contains(cmd, "schtasks") && ci_contains(cmd, "/create")) || eid == 4698 ||
                    ci_contains(etype, "task_created") || (ci_contains(msg, "scheduled task") && ci_contains(msg, "creat")))
                    evidence = "Scheduled task: " + (cmd.empty() ? msg : cmd).substr(0, 200);
            }
            else if (qid == "T1543.003") {
                if ((ci_contains(cmd, "sc") && ci_contains(cmd, "create") && ci_contains(cmd, "binpath")) ||
                    eid == 7045 || ci_contains(etype, "service_installed") ||
                    (ci_contains(msg, "service") && ci_contains(msg, "install")))
                    evidence = "Service: " + (cmd.empty() ? msg : cmd).substr(0, 200);
            }
            else if (qid == "T1547.001") {
                if ((ci_contains(cmd, "reg") && ci_contains(cmd, "add") && (ci_contains(cmd, "\\run") || ci_contains(cmd, "\\runonce"))) ||
                    ci_contains(msg, "\\currentversion\\run") || ci_contains(msg, "\\runonce") ||
                    ci_contains(msg, "\\winlogon\\shell"))
                    evidence = "Registry persistence: " + (cmd.empty() ? msg : cmd).substr(0, 200);
            }
            else if (qid == "T1505.003") {
                if ((ci_contains(parent, "w3wp") || ci_contains(parent, "httpd") || ci_contains(parent, "nginx") ||
                     ci_contains(parent, "apache") || ci_contains(parent, "tomcat") || ci_contains(parent, "java")) &&
                    (ci_contains(proc, "cmd") || ci_contains(proc, "powershell") || ci_contains(proc, "bash") || ci_contains(proc, "sh")))
                    evidence = "Web shell: " + parent + " → " + proc;
            }
            else if (qid == "T1074") {
                if ((ci_contains(cmd, "rar") || ci_contains(cmd, "7z") || ci_contains(cmd, "zip") || ci_contains(cmd, "tar")) &&
                    (ci_contains(cmd, "-p") || ci_contains(cmd, "password") || ci_contains(cmd, "\\temp") || ci_contains(cmd, "/tmp")))
                    evidence = "Data staging: " + cmd.substr(0, 200);
            }
            else if (qid == "T1562.001") {
                if (ci_contains(cmd, "set-mppreference") || ci_contains(cmd, "disablerealtimemonitoring") ||
                    ci_contains(cmd, "add-mppreference") && ci_contains(cmd, "exclusion") ||
                    ci_contains(cmd, "netsh") && ci_contains(cmd, "firewall") && ci_contains(cmd, "disable") ||
                    ci_contains(cmd, "sc stop") && (ci_contains(cmd, "windefend") || ci_contains(cmd, "mpssvc")) ||
                    ci_contains(cmd, "tamperprotection") || ci_contains(cmd, "disableantispyware"))
                    evidence = "Security tool tamper: " + cmd.substr(0, 200);
            }
            else if (qid == "T1105") {
                if ((ci_contains(cmd, "curl") || ci_contains(cmd, "wget") || ci_contains(cmd, "invoke-webrequest") ||
                     ci_contains(cmd, "downloadfile") || ci_contains(cmd, "downloadstring") ||
                     ci_contains(cmd, "bitsadmin") && ci_contains(cmd, "/transfer") ||
                     ci_contains(cmd, "certutil") && ci_contains(cmd, "-urlcache")) &&
                    (ci_contains(cmd, "http") || ci_contains(cmd, "ftp")))
                    evidence = "Remote download: " + cmd.substr(0, 200);
            }
            else if (qid == "T1027") {
                if (ci_contains(cmd, "frombase64string") || ci_contains(cmd, "tobase64string") ||
                    ci_contains(cmd, "[convert]::") || ci_contains(cmd, "-bxor") ||
                    ci_contains(cmd, "char]") && ci_contains(cmd, "join") ||
                    ci_contains(cmd, "replace") && ci_contains(cmd, "char"))
                    evidence = "Obfuscation: " + cmd.substr(0, 200);
            }
            else if (qid == "T1036") {
                if ((ci_contains(proc, "svchost") && !ci_contains(cmd, "\\system32\\")) ||
                    (ci_contains(proc, "csrss") && !ci_contains(cmd, "\\system32\\")) ||
                    (ci_contains(proc, "lsass") && !ci_contains(cmd, "\\system32\\")) ||
                    (ci_contains(proc, "services") && !ci_contains(cmd, "\\system32\\")))
                    evidence = "Masquerading: " + proc + " from unusual path: " + cmd.substr(0, 150);
            }
            else if (qid == "T1055") {
                if (ci_contains(etype, "remote_thread") || ci_contains(etype, "createremotethread") ||
                    ci_contains(etype, "process_injection") || ci_contains(etype, "memory_allocation") ||
                    eid == 8 || eid == 10)  // Sysmon CreateRemoteThread, ProcessAccess
                    evidence = "Process injection: " + msg.substr(0, 200);
            }
            else if (qid == "T1082") {
                if (ci_contains(cmd, "systeminfo") || ci_contains(cmd, "hostname") ||
                    ci_contains(cmd, "whoami") || ci_contains(cmd, "ipconfig") ||
                    ci_contains(cmd, "uname -a") || ci_contains(cmd, "cat /etc/os-release") ||
                    ci_contains(cmd, "ver") && ci_contains(proc, "cmd"))
                    evidence = "System discovery: " + cmd.substr(0, 200);
            }
            else if (qid == "T1087") {
                if (ci_contains(cmd, "net user") || ci_contains(cmd, "net localgroup") ||
                    ci_contains(cmd, "net group") || ci_contains(cmd, "wmic useraccount") ||
                    ci_contains(cmd, "get-aduser") || ci_contains(cmd, "get-adgroupmember") ||
                    ci_contains(cmd, "cat /etc/passwd") || ci_contains(cmd, "getent passwd"))
                    evidence = "Account discovery: " + cmd.substr(0, 200);
            }
            else if (qid == "T1018") {
                if (ci_contains(cmd, "net view") || ci_contains(cmd, "ping -") || ci_contains(cmd, "ping sweep") ||
                    ci_contains(cmd, "arp -a") || ci_contains(cmd, "nslookup") ||
                    ci_contains(cmd, "nbtstat") || ci_contains(cmd, "nltest") ||
                    ci_contains(cmd, "dsquery") || ci_contains(cmd, "get-adcomputer"))
                    evidence = "Remote system discovery: " + cmd.substr(0, 200);
            }
            else if (qid == "T1049") {
                if (ci_contains(cmd, "netstat") || ci_contains(cmd, "ss -") ||
                    ci_contains(cmd, "net session") || ci_contains(cmd, "net use") ||
                    ci_contains(cmd, "established") || ci_contains(cmd, "get-nettcpconnection"))
                    evidence = "Network connection discovery: " + cmd.substr(0, 200);
            }
            else if (qid == "T1057") {
                if (ci_contains(cmd, "tasklist") || ci_contains(cmd, "get-process") ||
                    ci_contains(cmd, "wmic process") || ci_contains(cmd, "ps aux") ||
                    ci_contains(cmd, "ps -ef"))
                    evidence = "Process discovery: " + cmd.substr(0, 200);
            }
            else if (qid == "T1102") {
                if (eid == 1102 || ci_contains(etype, "audit_log_cleared"))
                    evidence = "Audit log cleared (EventID 1102): " + msg.substr(0, 200);
            }
            else if (qid == "T1136") {
                if (eid == 4720 || ci_contains(etype, "user_account_created") ||
                    (ci_contains(cmd, "net user") && ci_contains(cmd, "/add")) ||
                    (ci_contains(cmd, "useradd") || ci_contains(cmd, "adduser")))
                    evidence = "Account creation: " + (cmd.empty() ? msg : cmd).substr(0, 200);
            }

            if (!evidence.empty() && matches.size() < 20) {
                matches.push_back({{"event", ev_json(ev)}, {"evidence", evidence}});
            }
        }
        add_result(pq.id, pq.name, pq.desc, pq.mitre, pq.cat, pq.sev, matches);
    }

    // Sort by severity (critical first)
    std::sort(results.begin(), results.end(), [](const json& a, const json& b) {
        static const std::unordered_map<std::string, int> sev_order = {
            {"critical", 0}, {"high", 1}, {"medium", 2}, {"low", 3}, {"info", 4}
        };
        int sa = 4, sb = 4;
        if (a.contains("query")) {
            auto it = sev_order.find(a["query"].value("severity", "info"));
            if (it != sev_order.end()) sa = it->second;
        }
        if (b.contains("query")) {
            auto it = sev_order.find(b["query"].value("severity", "info"));
            if (it != sev_order.end()) sb = it->second;
        }
        return sa < sb;
    });

    return results;
}

}  // namespace shieldtier
