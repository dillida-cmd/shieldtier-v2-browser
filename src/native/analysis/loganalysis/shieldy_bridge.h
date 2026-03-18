#pragma once

#include <string>

#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

/// Bridges to the Shieldy Python log analyzer by spawning it as a subprocess.
/// Captures its JSON stdout and returns structured analysis results.
class ShieldyBridge {
public:
    struct ShieldyResult {
        json events;           // NormalizedEvent[] (capped at 5000)
        json insights;         // LogInsight[]
        json triage;           // LogTriage
        json investigation;    // LogInvestigation
        json graph;            // LogGraph
        json verdict;          // LogVerdict
        json hunting;          // HuntingQueryResult[]
        std::string format;
        int event_count = 0;
        int parse_errors = 0;
        json severity_counts;
        json category_counts;
    };

    ShieldyBridge();

    /// Check if the Shieldy bridge is available (python3 + bridge script found).
    bool available() const;

    /// Run Shieldy analysis on a file. Returns structured result or error.
    Result<ShieldyResult> analyze(const std::string& file_path);

private:
    std::string python_path_;   // resolved path to python3
    std::string bridge_path_;   // resolved path to shieldy_cli_bridge.py

    static std::string find_python();
    static std::string find_bridge_script();
};

}  // namespace shieldtier
