#include "scoring/scoring_engine.h"

#include <algorithm>
#include <cmath>
#include <set>

namespace shieldtier {

ScoringEngine::ScoringEngine() {
    weights_[AnalysisEngine::kYara]         = 0.30;
    weights_[AnalysisEngine::kSandbox]      = 0.25;
    weights_[AnalysisEngine::kFileAnalysis] = 0.15;
    weights_[AnalysisEngine::kAdvanced]     = 0.15;
    weights_[AnalysisEngine::kEnrichment]   = 0.10;
    weights_[AnalysisEngine::kContent]      = 0.05;
}

Result<ThreatVerdict> ScoringEngine::score(
    const std::vector<AnalysisEngineResult>& results) {
    if (results.empty()) {
        ThreatVerdict verdict;
        verdict.verdict = Verdict::kUnknown;
        verdict.confidence = 0.0;
        verdict.threat_score = 0;
        verdict.risk_level = "none";
        return verdict;
    }

    double weighted_sum = 0.0;
    double active_weight_sum = 0.0;
    int engines_with_findings = 0;
    std::vector<Finding> all_findings;

    for (const auto& result : results) {
        double engine_score = compute_engine_score(result);

        auto wit = weights_.find(result.engine);
        double w = (wit != weights_.end()) ? wit->second : 0.05;

        weighted_sum += engine_score * w;
        active_weight_sum += w;

        if (!result.findings.empty()) {
            engines_with_findings++;
        }

        all_findings.insert(all_findings.end(),
                            result.findings.begin(),
                            result.findings.end());
    }

    int threat_score = 0;
    if (active_weight_sum > 0.0) {
        threat_score = static_cast<int>(
            std::round(weighted_sum / active_weight_sum));
    }
    threat_score = std::clamp(threat_score, 0, 100);

    ThreatVerdict verdict;
    verdict.verdict = classify(threat_score);
    verdict.threat_score = threat_score;
    verdict.risk_level = risk_level(threat_score);
    verdict.confidence = compute_confidence(results, engines_with_findings);
    verdict.findings = std::move(all_findings);
    verdict.mitre_techniques = extract_mitre_techniques(results);
    verdict.details = nlohmann::json{
        {"engines_run", static_cast<int>(results.size())},
        {"engines_with_findings", engines_with_findings},
        {"active_weight_sum", active_weight_sum}
    };

    return verdict;
}

void ScoringEngine::set_weights(const std::vector<EngineWeight>& weights) {
    weights_.clear();
    for (const auto& ew : weights) {
        weights_[ew.engine] = ew.weight;
    }
}

std::vector<EngineWeight> ScoringEngine::get_weights() const {
    std::vector<EngineWeight> result;
    result.reserve(weights_.size());
    for (const auto& [engine, weight] : weights_) {
        result.push_back({engine, weight});
    }
    return result;
}

double ScoringEngine::compute_engine_score(const AnalysisEngineResult& result) {
    if (!result.success) {
        return 0.0;
    }

    double score = 0.0;
    for (const auto& finding : result.findings) {
        score += severity_weight(finding.severity);
    }

    return std::min(score, 100.0);
}

double ScoringEngine::severity_weight(Severity severity) {
    switch (severity) {
        case Severity::kInfo:     return 2.0;
        case Severity::kLow:      return 10.0;
        case Severity::kMedium:   return 25.0;
        case Severity::kHigh:     return 50.0;
        case Severity::kCritical: return 80.0;
    }
    return 0.0;
}

Verdict ScoringEngine::classify(int threat_score) {
    if (threat_score < 25) {
        return Verdict::kClean;
    } else if (threat_score <= 65) {
        return Verdict::kSuspicious;
    } else {
        return Verdict::kMalicious;
    }
}

std::string ScoringEngine::risk_level(int threat_score) {
    if (threat_score <= 10) {
        return "none";
    } else if (threat_score <= 25) {
        return "low";
    } else if (threat_score <= 50) {
        return "medium";
    } else if (threat_score <= 75) {
        return "high";
    } else {
        return "critical";
    }
}

double ScoringEngine::compute_confidence(
    const std::vector<AnalysisEngineResult>& results,
    int engines_with_findings) {
    int engine_count = static_cast<int>(results.size());

    double base;
    if (engine_count <= 1) {
        base = 0.3;
    } else if (engine_count == 2) {
        base = 0.5;
    } else {
        // 3+ engines: scale linearly from 0.6 to 0.95
        // At 3 engines: 0.6, at 8+ engines: 0.95
        double t = std::min(static_cast<double>(engine_count - 3) / 5.0, 1.0);
        base = 0.6 + t * 0.35;
    }

    // Corroboration boost: if a high-severity finding appears and at least
    // two engines reported findings, boost confidence
    if (engines_with_findings >= 2) {
        bool has_high_severity = false;
        for (const auto& result : results) {
            for (const auto& finding : result.findings) {
                if (finding.severity == Severity::kHigh ||
                    finding.severity == Severity::kCritical) {
                    has_high_severity = true;
                    break;
                }
            }
            if (has_high_severity) break;
        }
        if (has_high_severity) {
            base += 0.1;
        }
    }

    return std::min(base, 1.0);
}

std::vector<std::string> ScoringEngine::extract_mitre_techniques(
    const std::vector<AnalysisEngineResult>& results) {
    std::set<std::string> techniques;

    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            if (!finding.metadata.is_object()) continue;

            for (const auto& [key, value] : finding.metadata.items()) {
                if (key == "mitre" || key == "technique_id") {
                    if (value.is_string()) {
                        techniques.insert(value.get<std::string>());
                    } else if (value.is_array()) {
                        for (const auto& item : value) {
                            if (item.is_string()) {
                                techniques.insert(item.get<std::string>());
                            }
                        }
                    }
                }
            }
        }
    }

    return {techniques.begin(), techniques.end()};
}

}  // namespace shieldtier
