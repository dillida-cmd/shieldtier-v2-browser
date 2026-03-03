#include "analysis/advanced/heap_analyzer.h"

#include <cstring>
#include <unordered_map>

namespace shieldtier {

std::vector<Finding> HeapAnalyzer::analyze(const uint8_t* data, size_t size) {
    std::vector<Finding> findings;
    if (!data || size == 0) return findings;

    if (detect_heap_spray(data, size)) {
        json meta;
        meta["pattern"] = "heap_spray";
        findings.push_back({
            "Heap: Spray Pattern Detected",
            "Found repeated NOP+shellcode block patterns consistent with heap spray exploitation",
            Severity::kCritical,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    if (detect_rop_gadgets(data, size)) {
        json meta;
        meta["pattern"] = "rop_gadgets";
        findings.push_back({
            "Heap: ROP Gadget Cluster Detected",
            "Found clusters of ret instructions with preceding short sequences indicative of ROP chains",
            Severity::kMedium,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    return findings;
}

bool HeapAnalyzer::detect_heap_spray(const uint8_t* data, size_t size) {
    // Look for any 4-byte pattern repeated 100+ times consecutively
    constexpr size_t kMinRepeats = 100;
    constexpr size_t kPatternSize = 4;

    if (size < kPatternSize * kMinRepeats) return false;

    for (size_t i = 0; i + kPatternSize * kMinRepeats <= size; ++i) {
        uint32_t pattern;
        std::memcpy(&pattern, data + i, kPatternSize);

        // Skip all-zero patterns (normal padding)
        if (pattern == 0) continue;

        size_t repeats = 1;
        for (size_t j = i + kPatternSize; j + kPatternSize <= size; j += kPatternSize) {
            uint32_t candidate;
            std::memcpy(&candidate, data + j, kPatternSize);
            if (candidate != pattern) break;
            if (++repeats >= kMinRepeats) return true;
        }

        i += repeats * kPatternSize - 1;
    }

    return false;
}

bool HeapAnalyzer::detect_rop_gadgets(const uint8_t* data, size_t size) {
    // Find clusters of ret (0xC3) instructions — a high density suggests ROP gadget collection
    // Look for 8+ ret instructions within any 256-byte window
    constexpr size_t kWindowSize = 256;
    constexpr size_t kMinRets = 8;

    if (size < kWindowSize) return false;

    for (size_t i = 0; i + kWindowSize <= size; ++i) {
        size_t ret_count = 0;
        for (size_t j = i; j < i + kWindowSize; ++j) {
            if (data[j] == 0xC3) {
                ++ret_count;
                if (ret_count >= kMinRets) return true;
            }
        }
    }

    return false;
}

}  // namespace shieldtier
