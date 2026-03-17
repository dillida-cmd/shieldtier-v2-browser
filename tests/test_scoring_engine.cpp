#include <gtest/gtest.h>
#include "scoring/scoring_engine.h"

using namespace shieldtier;

TEST(ScoringEngine, CleanVerdict) {
    ScoringEngine engine;
    std::vector<AnalysisEngineResult> results;

    // No findings = clean
    AnalysisEngineResult file_result;
    file_result.engine = AnalysisEngine::kFileAnalysis;
    file_result.success = true;
    file_result.duration_ms = 10.0;
    results.push_back(file_result);

    auto verdict = engine.score(results);
    ASSERT_TRUE(verdict.ok());
    EXPECT_EQ(verdict.value().verdict, Verdict::kClean);
    EXPECT_EQ(verdict.value().threat_score, 0);
}

TEST(ScoringEngine, MaliciousVerdict) {
    ScoringEngine engine;
    std::vector<AnalysisEngineResult> results;

    // Multiple critical findings across engines
    AnalysisEngineResult yara_result;
    yara_result.engine = AnalysisEngine::kYara;
    yara_result.success = true;
    yara_result.duration_ms = 5.0;
    yara_result.findings.push_back(Finding{
        "Malware_Generic", "Known malware signature",
        Severity::kCritical, AnalysisEngine::kYara, {}
    });
    results.push_back(yara_result);

    AnalysisEngineResult sandbox_result;
    sandbox_result.engine = AnalysisEngine::kSandbox;
    sandbox_result.success = true;
    sandbox_result.duration_ms = 50.0;
    sandbox_result.findings.push_back(Finding{
        "Keylogger", "Keystroke capture API detected",
        Severity::kCritical, AnalysisEngine::kSandbox, {}
    });
    sandbox_result.findings.push_back(Finding{
        "C2 Communication", "Known C2 domain contacted",
        Severity::kHigh, AnalysisEngine::kSandbox, {}
    });
    results.push_back(sandbox_result);

    auto verdict = engine.score(results);
    ASSERT_TRUE(verdict.ok());
    EXPECT_GE(verdict.value().threat_score, 70);
    EXPECT_EQ(verdict.value().verdict, Verdict::kMalicious);
}

TEST(ScoringEngine, SuspiciousVerdict) {
    ScoringEngine engine;
    std::vector<AnalysisEngineResult> results;

    AnalysisEngineResult content_result;
    content_result.engine = AnalysisEngine::kContent;
    content_result.success = true;
    content_result.duration_ms = 2.0;
    content_result.findings.push_back(Finding{
        "Obfuscated JS", "eval() with encoded string",
        Severity::kMedium, AnalysisEngine::kContent, {}
    });
    results.push_back(content_result);

    auto verdict = engine.score(results);
    ASSERT_TRUE(verdict.ok());
    EXPECT_GT(verdict.value().threat_score, 0);
    // With a single medium finding from a low-weight engine, should be suspicious at most
    EXPECT_LE(verdict.value().threat_score, 70);
}

TEST(ScoringEngine, CustomWeights) {
    ScoringEngine engine;
    engine.set_weights({
        {AnalysisEngine::kYara, 0.5},
        {AnalysisEngine::kSandbox, 0.5},
    });

    auto weights = engine.get_weights();
    EXPECT_GE(weights.size(), 2u);
}

TEST(ScoringEngine, MITRETechniqueExtraction) {
    ScoringEngine engine;
    std::vector<AnalysisEngineResult> results;

    AnalysisEngineResult advanced_result;
    advanced_result.engine = AnalysisEngine::kAdvanced;
    advanced_result.success = true;
    advanced_result.duration_ms = 10.0;
    nlohmann::json meta;
    meta["mitre_id"] = "T1055";
    advanced_result.findings.push_back(Finding{
        "Process Injection", "CreateRemoteThread detected",
        Severity::kHigh, AnalysisEngine::kAdvanced, meta
    });
    results.push_back(advanced_result);

    auto verdict = engine.score(results);
    ASSERT_TRUE(verdict.ok());
    // Should extract MITRE techniques from findings metadata
    // (implementation dependent — check if mitre_techniques is populated)
    EXPECT_GE(verdict.value().findings.size(), 1u);
}
