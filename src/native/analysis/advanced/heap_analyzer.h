#pragma once

#include <cstdint>
#include <vector>

#include "common/types.h"

namespace shieldtier {

class HeapAnalyzer {
public:
    std::vector<Finding> analyze(const uint8_t* data, size_t size);

private:
    bool detect_heap_spray(const uint8_t* data, size_t size);
    bool detect_rop_gadgets(const uint8_t* data, size_t size);
};

}  // namespace shieldtier
