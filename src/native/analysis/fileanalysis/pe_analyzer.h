#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

struct PeSection {
    std::string name;
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t characteristics;
    double entropy;
};

struct PeImport {
    std::string dll_name;
    std::string function_name;
};

struct PeSecurityFeatures {
    bool aslr;
    bool dep;
    bool cfg;
    bool seh;
    bool authenticode;
};

struct PeInfo {
    bool is_64bit;
    bool is_dll;
    uint32_t entry_point;
    uint16_t subsystem;
    std::string compile_timestamp;
    std::vector<PeSection> sections;
    std::vector<PeImport> imports;
    PeSecurityFeatures security;
    std::vector<std::string> suspicious_imports;
};

class PeAnalyzer {
public:
    Result<PeInfo> analyze(const FileBuffer& file);
    std::vector<Finding> generate_findings(const PeInfo& info);

private:
    double calculate_section_entropy(const uint8_t* data, size_t size);
    std::vector<std::string> check_suspicious_imports(
        const std::vector<PeImport>& imports);
};

}  // namespace shieldtier
