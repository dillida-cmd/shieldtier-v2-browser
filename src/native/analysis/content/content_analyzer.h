#pragma once

#include <string>
#include <vector>

#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

class ContentAnalyzer {
public:
    ContentAnalyzer();
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    std::vector<Finding> analyze_html(const std::string& content);
    std::vector<Finding> analyze_javascript(const std::string& content);

    bool detect_phishing_form(const std::string& html);
    bool detect_drive_by_download(const std::string& html);
    bool detect_obfuscated_js(const std::string& js);
    int count_iframes(const std::string& html);
};

}  // namespace shieldtier
