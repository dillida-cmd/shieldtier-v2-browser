#pragma once

#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

class AdvancedEngine {
public:
    AdvancedEngine();
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    std::vector<Finding> run_pe_capability(const FileBuffer& file);
    std::vector<Finding> run_shellcode_detection(const FileBuffer& file);
    std::vector<Finding> run_script_analysis(const FileBuffer& file);
    std::vector<Finding> run_heap_analysis(const FileBuffer& file);
};

}  // namespace shieldtier
