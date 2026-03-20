#pragma once

#include <string>
#include <vector>

#include "common/types.h"

namespace shieldtier {

struct NormalizedEvent;

class LogDetector {
public:
    LogDetector();

    std::vector<Finding> detect(const std::vector<NormalizedEvent>& events);

private:
    std::vector<Finding> detect_brute_force(const std::vector<NormalizedEvent>& events);
    std::vector<Finding> detect_lateral_movement(const std::vector<NormalizedEvent>& events);
    std::vector<Finding> detect_privilege_escalation(const std::vector<NormalizedEvent>& events);
    std::vector<Finding> detect_data_exfiltration(const std::vector<NormalizedEvent>& events);
    std::vector<Finding> detect_suspicious_commands(const std::vector<NormalizedEvent>& events);
    std::vector<Finding> detect_account_manipulation(const std::vector<NormalizedEvent>& events);
    std::vector<Finding> detect_log_clearing(const std::vector<NormalizedEvent>& events);
    std::vector<Finding> detect_rdp_abuse(const std::vector<NormalizedEvent>& events);
};

}  // namespace shieldtier
