/// ShieldTier Log Analysis UAT — runs every test file through the full pipeline
/// Build: From the build/ directory, the test binary already links this.
/// Run:   ./tests/shieldtier_tests --gtest_filter=LogAnalysisUAT.*

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "analysis/loganalysis/log_manager.h"
#include "analysis/loganalysis/log_normalizer.h"
#include "analysis/loganalysis/log_analysis_engine.h"
#include "common/types.h"

using namespace shieldtier;

// Minimal standalone test runner (no gtest dependency needed)
static int tests_run = 0, tests_passed = 0, tests_failed = 0;

#define UAT_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "  FAIL: " << msg << std::endl; \
        tests_failed++; return; \
    } \
} while(0)

#define UAT_CHECK(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "  WARN: " << msg << std::endl; \
    } \
} while(0)

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data(sz);
    f.read(reinterpret_cast<char*>(data.data()), sz);
    return data;
}

struct TestResult {
    std::string name;
    int event_count;
    int insight_count;
    int hunting_count;
    bool has_triage;
    bool has_investigation;
    bool has_graph;
    bool has_verdict;
    std::string verdict;
    int confidence;
    std::vector<std::string> mitre_hits;
};

static TestResult run_analysis(const std::string& path, const std::string& name) {
    TestResult tr;
    tr.name = name;

    auto data = read_file(path);
    if (data.empty()) {
        std::cerr << "  ERROR: Could not read " << path << std::endl;
        return tr;
    }

    LogManager mgr;
    auto format = mgr.detect_format(data.data(), data.size());
    auto parse_result = mgr.parse(data.data(), data.size(), format);

    if (!parse_result.ok()) {
        std::cerr << "  ERROR: Parse failed: " << parse_result.error().message << std::endl;
        return tr;
    }

    auto& events = parse_result.value();
    tr.event_count = events.size();

    // Normalize events (extract canonical _user, _src_ip, _command from messages)
    LogNormalizer normalizer;
    normalizer.normalize(events);

    // Run detector
    FileBuffer fb;
    fb.data = data;
    fb.filename = name;
    fb.mime_type = "text/plain";
    auto analysis = mgr.analyze(fb);
    std::vector<Finding> findings;
    if (analysis.ok()) findings = analysis.value().findings;

    // Run full engine
    LogAnalysisEngine engine;
    auto result = engine.analyze(events, findings);

    tr.insight_count = result.insights.is_array() ? result.insights.size() : 0;
    tr.has_triage = !result.triage.is_null();
    tr.has_investigation = !result.investigation.is_null();
    tr.has_graph = !result.graph.is_null();
    tr.has_verdict = !result.verdict.is_null();

    if (tr.has_verdict) {
        tr.verdict = result.verdict.value("verdict", "unknown");
        tr.confidence = result.verdict.value("confidence", 0);
    }

    // Count hunting matches and extract MITRE IDs
    tr.hunting_count = 0;
    if (result.hunting.is_array()) {
        for (const auto& h : result.hunting) {
            int mc = h.value("matchCount", 0);
            tr.hunting_count += mc;
            if (h.contains("query") && h["query"].contains("mitre")) {
                tr.mitre_hits.push_back(h["query"]["mitre"].get<std::string>() +
                    " (" + std::to_string(mc) + " matches)");
            }
        }
    }

    return tr;
}

static void print_result(const TestResult& tr) {
    std::cout << "\n┌─────────────────────────────────────────────────────────┐" << std::endl;
    std::cout << "│ " << tr.name << std::endl;
    std::cout << "├─────────────────────────────────────────────────────────┤" << std::endl;
    std::cout << "│ Events:        " << tr.event_count << std::endl;
    std::cout << "│ Insights:      " << tr.insight_count << std::endl;
    std::cout << "│ Hunting Hits:  " << tr.hunting_count << std::endl;
    std::cout << "│ Triage:        " << (tr.has_triage ? "YES" : "NO") << std::endl;
    std::cout << "│ Investigation: " << (tr.has_investigation ? "YES" : "NO") << std::endl;
    std::cout << "│ Graph:         " << (tr.has_graph ? "YES" : "NO") << std::endl;
    std::cout << "│ Verdict:       " << (tr.has_verdict ? tr.verdict : "N/A")
              << " (" << tr.confidence << "%)" << std::endl;
    if (!tr.mitre_hits.empty()) {
        std::cout << "│ MITRE Detections:" << std::endl;
        for (const auto& h : tr.mitre_hits) {
            std::cout << "│   • " << h << std::endl;
        }
    }
    std::cout << "└─────────────────────────────────────────────────────────┘" << std::endl;
}

int main(int argc, char** argv) {
    std::string base = "tests/loganalysis/uat/";
    // Allow override from command line
    if (argc > 1) base = std::string(argv[1]) + "/";

    struct TestCase {
        std::string file;
        std::string name;
        int min_events;
        int min_hunting;
        std::string expected_verdict; // "" = any
    };

    std::vector<TestCase> cases = {
        {"01_auth_brute_force.log",    "Auth/SSH Brute Force (syslog)",    20, 1, ""},
        {"02_ransomware_attack.log",   "Ransomware Full Kill Chain",       15, 3, ""},
        {"03_defender_timeline.csv",   "Defender Timeline CSV Export",     15, 3, ""},
        {"04_c2_network.json",         "C2/Network JSON (firewall+IDS)",  15, 2, ""},
        {"05_cef_ids_alerts.log",      "CEF IDS Alert Stream",            10, 0, ""},
        {"06_apache_web_attack.log",   "Apache Web Attack Logs",          15, 0, ""},
        {"07_windows_security.log",    "Windows Security Events",         25, 5, ""},
        {"08_syslog_firewall.log",     "Syslog RFC5424 Firewall",         10, 1, ""},
        {"09_w3c_iis.log",            "W3C IIS Web Server Logs",          8,  0, ""},
    };

    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
    std::cout << " ShieldTier Log Analysis — Full UAT Suite" << std::endl;
    std::cout << " Test files: " << cases.size() << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;

    std::vector<TestResult> results;
    for (const auto& tc : cases) {
        tests_run++;
        auto tr = run_analysis(base + tc.file, tc.name);
        print_result(tr);
        results.push_back(tr);

        bool pass = true;
        if (tr.event_count < tc.min_events) {
            std::cerr << "  FAIL: Expected >= " << tc.min_events << " events, got " << tr.event_count << std::endl;
            pass = false;
        }
        if (tr.hunting_count < tc.min_hunting) {
            std::cerr << "  FAIL: Expected >= " << tc.min_hunting << " hunting matches, got " << tr.hunting_count << std::endl;
            pass = false;
        }
        if (!tr.has_triage) {
            std::cerr << "  FAIL: Triage should not be null" << std::endl;
            pass = false;
        }
        if (!tr.has_verdict) {
            std::cerr << "  FAIL: Verdict should not be null" << std::endl;
            pass = false;
        }
        if (!tc.expected_verdict.empty() && tr.verdict != tc.expected_verdict) {
            std::cerr << "  FAIL: Expected verdict '" << tc.expected_verdict << "', got '" << tr.verdict << "'" << std::endl;
            pass = false;
        }

        if (pass) {
            std::cout << "  ✓ PASS" << std::endl;
            tests_passed++;
        } else {
            tests_failed++;
        }
    }

    std::cout << "\n═══════════════════════════════════════════════════════════" << std::endl;
    std::cout << " RESULTS: " << tests_passed << "/" << tests_run << " passed";
    if (tests_failed > 0) std::cout << " (" << tests_failed << " FAILED)";
    std::cout << std::endl;

    // Summary table
    std::cout << "\n Format       | Events | Insights | Hunting | Verdict     | MITRE" << std::endl;
    std::cout << " -------------|--------|----------|---------|-------------|------" << std::endl;
    for (const auto& tr : results) {
        printf(" %-12s | %6d | %8d | %7d | %-11s | %zu techniques\n",
               tr.name.substr(0, 12).c_str(), tr.event_count, tr.insight_count,
               tr.hunting_count, (tr.verdict + " " + std::to_string(tr.confidence) + "%").c_str(),
               tr.mitre_hits.size());
    }

    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
