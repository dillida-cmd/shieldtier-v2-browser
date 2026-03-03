#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

struct EngineWeight {
    AnalysisEngine engine;
    double weight;  // 0.0 - 1.0
};

struct AnalysisEngineHash {
    size_t operator()(AnalysisEngine e) const {
        return std::hash<int>()(static_cast<int>(e));
    }
};

class ScoringEngine {
public:
    ScoringEngine();

    Result<ThreatVerdict> score(const std::vector<AnalysisEngineResult>& results);
    void set_weights(const std::vector<EngineWeight>& weights);
    std::vector<EngineWeight> get_weights() const;

private:
    double compute_engine_score(const AnalysisEngineResult& result);
    static double severity_weight(Severity severity);
    static Verdict classify(int threat_score);
    static std::string risk_level(int threat_score);
    static double compute_confidence(
        const std::vector<AnalysisEngineResult>& results,
        int engines_with_findings);
    static std::vector<std::string> extract_mitre_techniques(
        const std::vector<AnalysisEngineResult>& results);

    std::unordered_map<AnalysisEngine, double, AnalysisEngineHash> weights_;
};

}  // namespace shieldtier
