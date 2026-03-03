#pragma once

#include <vector>

#include "common/json.h"
#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

class VmScoring {
public:
    static Result<AnalysisEngineResult> score_vm_results(
        const std::vector<json>& events,
        const json& network_activity,
        double duration_ms);

private:
    static std::vector<Finding> events_to_findings(const std::vector<json>& events);
    static std::vector<Finding> network_to_findings(const json& network_activity);
};

}  // namespace shieldtier
