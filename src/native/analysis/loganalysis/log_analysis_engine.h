#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "common/json.h"
#include "common/types.h"
#include "analysis/loganalysis/log_manager.h"

namespace shieldtier {

/// Analyzes parsed log events to produce triage, investigation chains,
/// entity graph, verdict, hunting results, and insights — matching the
/// renderer's LogAnalysisResult shape exactly.
class LogAnalysisEngine {
public:
    struct Result {
        json insights;        // LogInsight[]
        json triage;          // LogTriage | null
        json investigation;   // LogInvestigation | null
        json graph;           // LogGraph | null
        json verdict;         // LogVerdict | null
        json hunting;         // HuntingQueryResult[] | null
    };

    /// Run all analysis on parsed events + detector findings.
    Result analyze(const std::vector<NormalizedEvent>& events,
                   const std::vector<Finding>& findings);

private:
    // ── Shared entity extraction ──
    struct EntityMaps {
        std::unordered_map<std::string, int> users;
        std::unordered_map<std::string, int> ips;
        std::unordered_map<std::string, int> hosts;
        std::unordered_map<std::string, int> processes;
        std::unordered_map<std::string, int> commands;
        std::unordered_map<std::string, int> external_ips;
        std::unordered_map<std::string, Severity> user_max_sev;
        std::unordered_map<std::string, Severity> ip_max_sev;
        std::unordered_map<std::string, Severity> host_max_sev;
        std::unordered_map<std::string, Severity> process_max_sev;
        std::string min_timestamp;
        std::string max_timestamp;
    };

    EntityMaps extract_entities(const std::vector<NormalizedEvent>& events);

    json build_insights(const EntityMaps& em,
                        const std::vector<NormalizedEvent>& events,
                        const std::vector<Finding>& findings);

    json build_triage(const EntityMaps& em,
                      const std::vector<NormalizedEvent>& events,
                      const std::vector<Finding>& findings);

    json build_investigation(const std::vector<NormalizedEvent>& events);

    json build_graph(const EntityMaps& em,
                     const std::vector<NormalizedEvent>& events);

    json build_verdict(const std::vector<NormalizedEvent>& events,
                       const std::vector<Finding>& findings,
                       const json& hunting_results);

    json build_hunting(const std::vector<NormalizedEvent>& events);

    // ── Helpers ──
    static std::string meta_str(const json& fields, const char* key);
    static bool ci_contains(const std::string& haystack, const std::string& needle);
    static std::string to_lower(const std::string& s);
    static Severity higher_sev(Severity a, Severity b);
    static std::string sev_str(Severity s);
    static bool is_private_ip(const std::string& ip);
    static bool is_noise_user(const std::string& user);
    static bool is_valid_entity(const std::string& val);
    static std::string mitre_for_finding(const std::string& title);
    static std::string kill_chain_phase(const std::string& mitre_id);
};

}  // namespace shieldtier
