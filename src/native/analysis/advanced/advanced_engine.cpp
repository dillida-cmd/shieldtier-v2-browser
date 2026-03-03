#include "analysis/advanced/advanced_engine.h"

#include <chrono>
#include <cctype>
#include <string>
#include <vector>

#include "analysis/advanced/heap_analyzer.h"
#include "analysis/advanced/pe_capability.h"
#include "analysis/advanced/script_analyzer.h"
#include "analysis/advanced/shellcode_detector.h"

namespace shieldtier {

AdvancedEngine::AdvancedEngine() = default;

Result<AnalysisEngineResult> AdvancedEngine::analyze(const FileBuffer& file) {
    auto start = std::chrono::steady_clock::now();

    std::vector<Finding> all_findings;

    auto pe = run_pe_capability(file);
    all_findings.insert(all_findings.end(), pe.begin(), pe.end());

    auto sc = run_shellcode_detection(file);
    all_findings.insert(all_findings.end(), sc.begin(), sc.end());

    auto sa = run_script_analysis(file);
    all_findings.insert(all_findings.end(), sa.begin(), sa.end());

    auto ha = run_heap_analysis(file);
    all_findings.insert(all_findings.end(), ha.begin(), ha.end());

    auto end = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kAdvanced;
    result.success = true;
    result.findings = std::move(all_findings);
    result.duration_ms = duration;
    result.raw_output = json{
        {"sub_engines", {"pe_capability", "shellcode_detector", "script_analyzer", "heap_analyzer"}},
        {"total_findings", result.findings.size()}
    };

    return result;
}

std::vector<Finding> AdvancedEngine::run_pe_capability(const FileBuffer& file) {
    // Extract printable strings that look like API imports from the binary
    std::vector<std::string> imports;
    std::string current;

    for (size_t i = 0; i < file.size(); ++i) {
        char c = static_cast<char>(file.ptr()[i]);
        if (std::isprint(static_cast<unsigned char>(c))) {
            current += c;
        } else {
            if (current.size() >= 4) {
                imports.push_back(std::move(current));
            }
            current.clear();
        }
    }
    if (current.size() >= 4) {
        imports.push_back(std::move(current));
    }

    PeCapability analyzer;
    return analyzer.analyze(imports);
}

std::vector<Finding> AdvancedEngine::run_shellcode_detection(const FileBuffer& file) {
    ShellcodeDetector detector;
    return detector.scan(file.ptr(), file.size());
}

std::vector<Finding> AdvancedEngine::run_script_analysis(const FileBuffer& file) {
    ScriptAnalyzer analyzer;
    return analyzer.analyze(file.ptr(), file.size());
}

std::vector<Finding> AdvancedEngine::run_heap_analysis(const FileBuffer& file) {
    HeapAnalyzer analyzer;
    return analyzer.analyze(file.ptr(), file.size());
}

}  // namespace shieldtier
