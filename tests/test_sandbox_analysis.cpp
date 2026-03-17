#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <vector>

#include "analysis/sandbox/sandbox_engine.h"
#include "analysis/sandbox/behavior_signatures.h"
#include "analysis/sandbox/network_profiler.h"
#include "analysis/fileanalysis/file_analyzer.h"
#include "analysis/content/content_analyzer.h"
#include "scoring/scoring_engine.h"

using namespace shieldtier;

namespace fs = std::filesystem;

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

static std::string get_test_data_dir() {
    // Try relative to CWD first, then from build dir
    for (const char* path : {
        "tests/uat-data",
        "../tests/uat-data",
        "../../tests/uat-data",
    }) {
        if (fs::exists(path)) return path;
    }
    return "tests/uat-data";
}

// ============================================================
// TEST: Fake PE with suspicious API strings
// ============================================================

class SandboxAnalysisTest : public ::testing::Test {
protected:
    std::string data_dir = get_test_data_dir();
};

TEST_F(SandboxAnalysisTest, FakeMalwarePE_FileType) {
    auto data = read_file(data_dir + "/fake-malware-sample.exe");
    ASSERT_GT(data.size(), 64u);

    auto type = FileAnalyzer::detect_type(data.data(), data.size());
    EXPECT_EQ(type, FileType::kPE) << "Should detect MZ header as PE";
}

TEST_F(SandboxAnalysisTest, FakeMalwarePE_HighEntropy) {
    auto data = read_file(data_dir + "/fake-malware-sample.exe");
    ASSERT_GT(data.size(), 0u);

    double entropy = FileAnalyzer::calculate_entropy(data.data(), data.size());
    EXPECT_GT(entropy, 5.0) << "File with random data should have high entropy";
}

TEST_F(SandboxAnalysisTest, FakeMalwarePE_StringExtraction) {
    auto data = read_file(data_dir + "/fake-malware-sample.exe");
    ASSERT_GT(data.size(), 0u);

    auto strings = FileAnalyzer::extract_strings(data.data(), data.size(), 4, 5000);
    EXPECT_GT(strings.size(), 10u) << "Should extract suspicious API strings";

    // Check for specific suspicious strings
    bool found_virtual_alloc = false;
    bool found_create_remote_thread = false;
    bool found_c2_url = false;
    for (const auto& s : strings) {
        if (s.find("VirtualAllocEx") != std::string::npos) found_virtual_alloc = true;
        if (s.find("CreateRemoteThread") != std::string::npos) found_create_remote_thread = true;
        if (s.find("malware-c2.evil.com") != std::string::npos) found_c2_url = true;
    }
    EXPECT_TRUE(found_virtual_alloc) << "Should find VirtualAllocEx string";
    EXPECT_TRUE(found_create_remote_thread) << "Should find CreateRemoteThread string";
    EXPECT_TRUE(found_c2_url) << "Should find C2 URL string";
}

TEST_F(SandboxAnalysisTest, FakeMalwarePE_SandboxEngine) {
    auto data = read_file(data_dir + "/fake-malware-sample.exe");
    ASSERT_GT(data.size(), 0u);

    FileBuffer fb;
    fb.data = std::move(data);
    fb.filename = "fake-malware-sample.exe";
    fb.mime_type = "application/x-msdownload";

    SandboxEngine engine;
    auto result = engine.analyze(fb);
    ASSERT_TRUE(result.ok()) << "Sandbox analysis should succeed";

    auto& findings = result.value().findings;
    EXPECT_GT(findings.size(), 0u) << "Should produce findings";

    // Check for specific detections
    bool found_process_injection = false;
    bool found_keylogger = false;
    bool found_download_exec = false;
    bool found_high_entropy = false;
    bool found_c2_port = false;
    bool found_suspicious_ip = false;

    for (const auto& f : findings) {
        if (f.title.find("process_injection") != std::string::npos) found_process_injection = true;
        if (f.title.find("keylogging") != std::string::npos) found_keylogger = true;
        if (f.title.find("download_execute") != std::string::npos) found_download_exec = true;
        if (f.title.find("high_entropy") != std::string::npos) found_high_entropy = true;
        if (f.title.find("C2") != std::string::npos ||
            f.description.find("C2") != std::string::npos) found_c2_port = true;
        if (f.description.find("185.234.72.19") != std::string::npos) found_suspicious_ip = true;
    }

    EXPECT_TRUE(found_process_injection) << "Should detect process injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)";
    EXPECT_TRUE(found_keylogger) << "Should detect keylogger (SetWindowsHookEx + GetAsyncKeyState)";
    EXPECT_TRUE(found_download_exec) << "Should detect download-execute (InternetOpen + InternetOpenUrl + CreateProcess)";
    EXPECT_TRUE(found_high_entropy) << "Should detect high entropy sections";

    // Print all findings for UAT log
    fprintf(stderr, "\n=== SANDBOX FINDINGS (%zu total) ===\n", findings.size());
    for (const auto& f : findings) {
        const char* sev_str = "?";
        switch (f.severity) {
            case Severity::kCritical: sev_str = "CRITICAL"; break;
            case Severity::kHigh: sev_str = "HIGH"; break;
            case Severity::kMedium: sev_str = "MEDIUM"; break;
            case Severity::kLow: sev_str = "LOW"; break;
            case Severity::kInfo: sev_str = "INFO"; break;
        }
        fprintf(stderr, "  [%s] %s\n         %s\n", sev_str, f.title.c_str(), f.description.c_str());
    }
    fprintf(stderr, "=== END ===\n\n");
}

// ============================================================
// TEST: PowerShell dropper script
// ============================================================

TEST_F(SandboxAnalysisTest, PowerShellDropper_SandboxEngine) {
    auto data = read_file(data_dir + "/suspicious-dropper.ps1");
    ASSERT_GT(data.size(), 0u);

    FileBuffer fb;
    fb.data = std::move(data);
    fb.filename = "suspicious-dropper.ps1";
    fb.mime_type = "application/x-powershell";

    SandboxEngine engine;
    auto result = engine.analyze(fb);
    ASSERT_TRUE(result.ok());

    auto& findings = result.value().findings;
    EXPECT_GT(findings.size(), 0u) << "Should detect suspicious patterns in PS1";

    bool found_encoded_cmd = false;
    bool found_run_key = false;
    bool found_schtasks = false;
    bool found_certutil = false;
    bool found_bitsadmin = false;
    bool found_wmic = false;
    bool found_defender = false;
    bool found_net_user = false;

    for (const auto& f : findings) {
        if (f.title.find("powershell_encoded") != std::string::npos) found_encoded_cmd = true;
        if (f.title.find("registry_run_key") != std::string::npos) found_run_key = true;
        if (f.title.find("scheduled_task") != std::string::npos) found_schtasks = true;
        if (f.title.find("certutil_decode") != std::string::npos) found_certutil = true;
        if (f.title.find("bitsadmin") != std::string::npos) found_bitsadmin = true;
        if (f.title.find("wmi_execution") != std::string::npos) found_wmic = true;
        if (f.title.find("disable_defender") != std::string::npos) found_defender = true;
        if (f.title.find("net_user") != std::string::npos || f.title.find("net_localgroup") != std::string::npos) found_net_user = true;
    }

    EXPECT_TRUE(found_encoded_cmd) << "Should detect -EncodedCommand";
    EXPECT_TRUE(found_run_key) << "Should detect registry Run key persistence";
    EXPECT_TRUE(found_schtasks) << "Should detect scheduled task creation";
    EXPECT_TRUE(found_certutil) << "Should detect certutil decode";
    EXPECT_TRUE(found_bitsadmin) << "Should detect BITS transfer";
    EXPECT_TRUE(found_wmic) << "Should detect WMI execution";
    EXPECT_TRUE(found_defender) << "Should detect Defender disable";
    EXPECT_TRUE(found_net_user) << "Should detect net user enumeration";

    fprintf(stderr, "\n=== PS1 DROPPER FINDINGS (%zu total) ===\n", findings.size());
    for (const auto& f : findings) {
        const char* sev_str = "?";
        switch (f.severity) {
            case Severity::kCritical: sev_str = "CRITICAL"; break;
            case Severity::kHigh: sev_str = "HIGH"; break;
            case Severity::kMedium: sev_str = "MEDIUM"; break;
            case Severity::kLow: sev_str = "LOW"; break;
            case Severity::kInfo: sev_str = "INFO"; break;
        }
        fprintf(stderr, "  [%s] %s\n         %s\n", sev_str, f.title.c_str(), f.description.c_str());
    }
    fprintf(stderr, "=== END ===\n\n");
}

// ============================================================
// TEST: Malicious HTML content analysis
// ============================================================

TEST_F(SandboxAnalysisTest, MaliciousHTML_ContentAnalyzer) {
    auto data = read_file(data_dir + "/test-malicious.html");
    ASSERT_GT(data.size(), 0u);

    FileBuffer fb;
    fb.data = std::move(data);
    fb.filename = "test-malicious.html";
    fb.mime_type = "text/html";

    ContentAnalyzer analyzer;
    auto result = analyzer.analyze(fb);
    ASSERT_TRUE(result.ok());

    auto& findings = result.value().findings;
    EXPECT_GT(findings.size(), 0u) << "Should detect malicious HTML patterns";

    fprintf(stderr, "\n=== HTML CONTENT FINDINGS (%zu total) ===\n", findings.size());
    for (const auto& f : findings) {
        const char* sev_str = "?";
        switch (f.severity) {
            case Severity::kCritical: sev_str = "CRITICAL"; break;
            case Severity::kHigh: sev_str = "HIGH"; break;
            case Severity::kMedium: sev_str = "MEDIUM"; break;
            case Severity::kLow: sev_str = "LOW"; break;
            case Severity::kInfo: sev_str = "INFO"; break;
        }
        fprintf(stderr, "  [%s] %s\n         %s\n", sev_str, f.title.c_str(), f.description.c_str());
    }
    fprintf(stderr, "=== END ===\n\n");
}

// ============================================================
// TEST: EICAR test file
// ============================================================

TEST_F(SandboxAnalysisTest, EICAR_FileAnalysis) {
    auto data = read_file(data_dir + "/eicar-test.txt");
    ASSERT_GT(data.size(), 0u);

    FileBuffer fb;
    fb.data = std::move(data);
    fb.filename = "eicar-test.txt";
    fb.mime_type = "application/octet-stream";

    FileAnalyzer analyzer;
    auto result = analyzer.analyze(fb);
    ASSERT_TRUE(result.ok());

    fprintf(stderr, "\n=== EICAR FILE ANALYSIS ===\n");
    fprintf(stderr, "  Findings: %zu\n", result.value().findings.size());
    fprintf(stderr, "  SHA256: %s\n", fb.sha256.c_str());
    for (const auto& f : result.value().findings) {
        fprintf(stderr, "  [%s] %s\n", f.title.c_str(), f.description.c_str());
    }
    fprintf(stderr, "=== END ===\n\n");
}

// ============================================================
// TEST: Multi-engine scoring
// ============================================================

TEST_F(SandboxAnalysisTest, FakeMalware_ScoringVerdict) {
    auto data = read_file(data_dir + "/fake-malware-sample.exe");
    ASSERT_GT(data.size(), 0u);

    FileBuffer fb;
    fb.data = std::move(data);
    fb.filename = "fake-malware-sample.exe";
    fb.mime_type = "application/x-msdownload";

    // Run through multiple engines
    FileAnalyzer file_analyzer;
    SandboxEngine sandbox_engine;

    auto file_result = file_analyzer.analyze(fb);
    auto sandbox_result = sandbox_engine.analyze(fb);

    ASSERT_TRUE(file_result.ok());
    ASSERT_TRUE(sandbox_result.ok());

    // Feed all results into scoring engine
    std::vector<AnalysisEngineResult> results;
    results.push_back(file_result.value());
    results.push_back(sandbox_result.value());

    ScoringEngine scorer;
    auto verdict = scorer.score(results);
    ASSERT_TRUE(verdict.ok());

    auto& v = verdict.value();
    fprintf(stderr, "\n=== MULTI-ENGINE SCORING ===\n");
    fprintf(stderr, "  Verdict: %s\n",
        v.verdict == Verdict::kMalicious ? "MALICIOUS" :
        v.verdict == Verdict::kSuspicious ? "SUSPICIOUS" :
        v.verdict == Verdict::kClean ? "CLEAN" : "UNKNOWN");
    fprintf(stderr, "  Threat Score: %d/100\n", v.threat_score);
    fprintf(stderr, "  Confidence: %.1f%%\n", v.confidence * 100);
    fprintf(stderr, "  Risk Level: %s\n", v.risk_level.c_str());
    fprintf(stderr, "  Total Findings: %zu\n", v.findings.size());
    fprintf(stderr, "  MITRE Techniques: %zu\n", v.mitre_techniques.size());
    for (const auto& t : v.mitre_techniques) {
        fprintf(stderr, "    - %s\n", t.c_str());
    }
    fprintf(stderr, "=== END ===\n\n");

    // With multiple critical findings from sandbox (process injection, keylogger, etc.),
    // the verdict should be at least suspicious, ideally malicious
    EXPECT_GE(v.threat_score, 25) << "Threat score should be at least 25 (suspicious)";
    EXPECT_NE(v.verdict, Verdict::kClean) << "Should NOT be clean";
}
