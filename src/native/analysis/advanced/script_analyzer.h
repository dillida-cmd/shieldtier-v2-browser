#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "common/types.h"

namespace shieldtier {

class ScriptAnalyzer {
public:
    std::vector<Finding> analyze(const uint8_t* data, size_t size);

private:
    std::vector<Finding> detect_powershell(const std::string& content);
    std::vector<Finding> detect_vba_macros(const std::string& content);
    std::vector<Finding> detect_javascript(const std::string& content);
    std::vector<Finding> detect_batch(const std::string& content);
    std::vector<Finding> detect_base64_payload(const std::string& content);
};

}  // namespace shieldtier
