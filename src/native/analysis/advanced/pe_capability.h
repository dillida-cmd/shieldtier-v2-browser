#pragma once

#include <string>
#include <vector>

#include "common/types.h"

namespace shieldtier {

struct Capability {
    std::string name;
    std::string mitre_id;
    std::string description;
    Severity severity;
    std::vector<std::string> apis;
};

class PeCapability {
public:
    PeCapability();
    std::vector<Finding> analyze(const std::vector<std::string>& imports);

private:
    std::vector<Capability> capabilities_;
};

}  // namespace shieldtier
