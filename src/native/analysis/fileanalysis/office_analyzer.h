#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

struct OfficeInfo {
    std::string format;  // "ooxml" or "ole2"
    bool has_macros;
    bool has_external_links;
    bool has_activex;
    bool has_embedded_objects;
    bool has_dde;
    size_t external_link_count;
    size_t embedded_object_count;
    std::vector<std::string> content_types;
    std::vector<std::string> auto_exec_triggers;
};

class OfficeAnalyzer {
public:
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    OfficeInfo analyze_ooxml(const uint8_t* data, size_t size);
    OfficeInfo analyze_ole2(const uint8_t* data, size_t size);
    std::vector<Finding> generate_findings(const OfficeInfo& info);
};

}  // namespace shieldtier
