#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

struct PdfInfo {
    std::string version;
    size_t page_count;
    size_t object_count;
    bool has_javascript;
    bool has_open_action;
    bool has_additional_actions;
    bool has_launch_actions;
    bool has_embedded_files;
    bool has_submit_form;
    bool has_encryption;
    double entropy;
    std::vector<std::string> uris;
};

class PdfAnalyzer {
public:
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    PdfInfo parse_structure(const uint8_t* data, size_t size);
    std::vector<Finding> generate_findings(const PdfInfo& info);
};

}  // namespace shieldtier
