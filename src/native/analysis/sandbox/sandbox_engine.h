#pragma once

#include <string>
#include <vector>

#include "common/json.h"
#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

struct BehaviorEvent {
    std::string type;
    std::string detail;
    json metadata;
    Severity severity;
};

class SandboxEngine {
public:
    SandboxEngine();

    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    std::vector<BehaviorEvent> analyze_import_behavior(
        const std::vector<std::string>& api_names);
    std::vector<BehaviorEvent> analyze_string_behavior(
        const std::vector<std::string>& strings);
    std::vector<BehaviorEvent> analyze_resource_behavior(
        const FileBuffer& file);
    std::vector<Finding> events_to_findings(
        const std::vector<BehaviorEvent>& events);

    /// Extract actual PE import function names via pe-parse.
    /// Falls back to string extraction if file is not a PE.
    std::vector<std::string> extract_api_names(const FileBuffer& file,
                                                const std::vector<std::string>& strings);
};

}  // namespace shieldtier
