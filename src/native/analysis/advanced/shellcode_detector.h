#pragma once

#include <cstdint>
#include <vector>

#include "common/types.h"

namespace shieldtier {

class ShellcodeDetector {
public:
    std::vector<Finding> scan(const uint8_t* data, size_t size);

private:
    bool detect_nop_sled(const uint8_t* data, size_t size, size_t& offset);
    bool detect_getpc(const uint8_t* data, size_t size, size_t& offset);
    bool detect_api_hash(const uint8_t* data, size_t size, size_t& offset);
    bool detect_xor_decode(const uint8_t* data, size_t size);
    bool detect_stack_strings(const uint8_t* data, size_t size);
};

}  // namespace shieldtier
