#include "analysis/advanced/shellcode_detector.h"

#include <cstring>

namespace shieldtier {

std::vector<Finding> ShellcodeDetector::scan(const uint8_t* data, size_t size) {
    std::vector<Finding> findings;
    if (!data || size == 0) return findings;

    size_t offset = 0;
    if (detect_nop_sled(data, size, offset)) {
        json meta;
        meta["pattern"] = "nop_sled";
        meta["offset"] = offset;
        findings.push_back({
            "Shellcode: NOP Sled Detected",
            "Found 16+ consecutive NOP (0x90) instructions typical of shellcode padding",
            Severity::kCritical,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    offset = 0;
    if (detect_getpc(data, size, offset)) {
        json meta;
        meta["pattern"] = "getpc";
        meta["offset"] = offset;
        findings.push_back({
            "Shellcode: GetPC Sequence Detected",
            "Found call $+5 or fstenv GetPC pattern used by position-independent shellcode",
            Severity::kHigh,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    offset = 0;
    if (detect_api_hash(data, size, offset)) {
        json meta;
        meta["pattern"] = "api_hash_ror13";
        meta["offset"] = offset;
        findings.push_back({
            "Shellcode: API Hashing (ROR13) Detected",
            "Found ROR EDI,13 instruction sequence used by Metasploit-style API resolution",
            Severity::kHigh,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    if (detect_xor_decode(data, size)) {
        json meta;
        meta["pattern"] = "xor_decode";
        findings.push_back({
            "Shellcode: XOR Decode Loop Detected",
            "Found XOR-encoded data that decodes to predominantly printable ASCII",
            Severity::kMedium,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    if (detect_stack_strings(data, size)) {
        json meta;
        meta["pattern"] = "stack_strings";
        findings.push_back({
            "Shellcode: Stack String Construction Detected",
            "Found multiple push+mov sequences consistent with building strings on the stack",
            Severity::kMedium,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    return findings;
}

bool ShellcodeDetector::detect_nop_sled(const uint8_t* data, size_t size, size_t& offset) {
    constexpr size_t kMinNops = 16;
    size_t consecutive = 0;
    for (size_t i = 0; i < size; ++i) {
        if (data[i] == 0x90) {
            if (++consecutive >= kMinNops) {
                offset = i - kMinNops + 1;
                return true;
            }
        } else {
            consecutive = 0;
        }
    }
    return false;
}

bool ShellcodeDetector::detect_getpc(const uint8_t* data, size_t size, size_t& offset) {
    // call $+5 pattern: E8 00 00 00 00 followed by pop reg (58-5F)
    for (size_t i = 0; i + 5 < size; ++i) {
        if (data[i] == 0xE8 &&
            data[i + 1] == 0x00 && data[i + 2] == 0x00 &&
            data[i + 3] == 0x00 && data[i + 4] == 0x00 &&
            (data[i + 5] & 0xF8) == 0x58) {
            offset = i;
            return true;
        }
    }

    // fstenv pattern: D9 EE D9 74 24 F4
    const uint8_t fstenv[] = {0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4};
    for (size_t i = 0; i + sizeof(fstenv) <= size; ++i) {
        if (std::memcmp(data + i, fstenv, sizeof(fstenv)) == 0) {
            offset = i;
            return true;
        }
    }

    return false;
}

bool ShellcodeDetector::detect_api_hash(const uint8_t* data, size_t size, size_t& offset) {
    // ROR EDI,13: C1 CF 0D
    for (size_t i = 0; i + 2 < size; ++i) {
        if (data[i] == 0xC1 && data[i + 1] == 0xCF && data[i + 2] == 0x0D) {
            offset = i;
            return true;
        }
    }
    return false;
}

bool ShellcodeDetector::detect_xor_decode(const uint8_t* data, size_t size) {
    // Try single-byte XOR keys 0x01-0xFF on sliding windows
    constexpr size_t kWindowSize = 64;
    constexpr double kPrintableThreshold = 0.60;
    constexpr size_t kMaxXorScanBytes = 2 * 1024 * 1024;
    size_t scan_size = std::min(size, kMaxXorScanBytes);

    if (scan_size < kWindowSize) return false;

    for (uint8_t key = 1; key != 0; ++key) {
        for (size_t i = 0; i + kWindowSize <= scan_size; i += kWindowSize) {
            size_t printable = 0;
            for (size_t j = 0; j < kWindowSize; ++j) {
                uint8_t decoded = data[i + j] ^ key;
                if (decoded >= 0x20 && decoded <= 0x7E) {
                    ++printable;
                }
            }
            if (static_cast<double>(printable) / kWindowSize >= kPrintableThreshold) {
                return true;
            }
        }
    }
    return false;
}

bool ShellcodeDetector::detect_stack_strings(const uint8_t* data, size_t size) {
    // Look for sequences of push imm32 (0x68) followed by mov [esp+N] patterns
    // A cluster of 4+ push instructions within 32 bytes suggests stack string construction
    constexpr size_t kMinPushes = 4;
    constexpr size_t kWindowSize = 32;

    if (size < kWindowSize) return false;

    for (size_t i = 0; i + kWindowSize <= size; ++i) {
        size_t push_count = 0;
        for (size_t j = i; j < i + kWindowSize && j + 4 < size; ++j) {
            if (data[j] == 0x68) {
                bool all_printable = true;
                for (size_t k = 1; k <= 4; ++k) {
                    uint8_t c = data[j + k];
                    if (c != 0x00 && (c < 0x20 || c > 0x7E)) {
                        all_printable = false;
                        break;
                    }
                }
                if (all_printable) ++push_count;
            }
        }
        if (push_count >= kMinPushes) return true;
    }
    return false;
}

}  // namespace shieldtier
