#pragma once

#include <string>
#include <vector>

#include "common/types.h"

namespace shieldtier {

class NetworkProfiler {
public:
    std::vector<Finding> profile(const std::vector<std::string>& strings,
                                 const std::vector<std::string>& imports);

private:
    std::vector<Finding> detect_c2_indicators(const std::vector<std::string>& strings);
    std::vector<Finding> detect_network_imports(const std::vector<std::string>& imports);
};

}  // namespace shieldtier
