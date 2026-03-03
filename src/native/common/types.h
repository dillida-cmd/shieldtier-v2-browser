#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace shieldtier {

enum class Tier { kFree, kPro, kTeam, kEnterprise };

NLOHMANN_JSON_SERIALIZE_ENUM(Tier, {
    {Tier::kFree, "free"},
    {Tier::kPro, "pro"},
    {Tier::kTeam, "team"},
    {Tier::kEnterprise, "enterprise"},
})

enum class Verdict { kClean, kSuspicious, kMalicious, kUnknown };

NLOHMANN_JSON_SERIALIZE_ENUM(Verdict, {
    {Verdict::kClean, "clean"},
    {Verdict::kSuspicious, "suspicious"},
    {Verdict::kMalicious, "malicious"},
    {Verdict::kUnknown, "unknown"},
})

enum class AnalysisEngine {
    kYara,
    kFileAnalysis,
    kSandbox,
    kAdvanced,
    kEnrichment,
    kEmail,
    kContent,
    kLogAnalysis,
    kThreatFeed,
    kScoring,
    kVmSandbox
};

NLOHMANN_JSON_SERIALIZE_ENUM(AnalysisEngine, {
    {AnalysisEngine::kYara, "yara"},
    {AnalysisEngine::kFileAnalysis, "file_analysis"},
    {AnalysisEngine::kSandbox, "sandbox"},
    {AnalysisEngine::kAdvanced, "advanced"},
    {AnalysisEngine::kEnrichment, "enrichment"},
    {AnalysisEngine::kEmail, "email"},
    {AnalysisEngine::kContent, "content"},
    {AnalysisEngine::kLogAnalysis, "log_analysis"},
    {AnalysisEngine::kThreatFeed, "threat_feed"},
    {AnalysisEngine::kScoring, "scoring"},
    {AnalysisEngine::kVmSandbox, "vm_sandbox"},
})

struct FileBuffer {
    std::vector<uint8_t> data;
    std::string filename;
    std::string mime_type;
    std::string sha256;

    size_t size() const { return data.size(); }
    const uint8_t* ptr() const { return data.data(); }
};

struct Finding {
    std::string title;
    std::string description;
    std::string severity;
    std::string engine;
    nlohmann::json metadata;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Finding, title, description, severity, engine, metadata)

struct AnalysisEngineResult {
    AnalysisEngine engine;
    bool success;
    std::string error;
    std::vector<Finding> findings;
    nlohmann::json raw_output;
    double duration_ms;
};

struct ThreatVerdict {
    Verdict verdict;
    double confidence;
    int threat_score;
    std::string risk_level;
    std::vector<Finding> findings;
    std::vector<std::string> mitre_techniques;
    nlohmann::json details;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ThreatVerdict, verdict, confidence, threat_score,
                                   risk_level, findings, mitre_techniques, details)

}  // namespace shieldtier
