#pragma once

#include <string>

#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

enum class ExportFormat { kJson, kHtml, kZip };

class ExportManager {
public:
    ExportManager();

    Result<std::string> export_json(const ThreatVerdict& verdict,
                                     const std::string& filename);
    Result<std::string> export_html(const ThreatVerdict& verdict,
                                     const std::string& filename);
    Result<std::string> export_zip(const ThreatVerdict& verdict,
                                    const std::string& filename,
                                    const std::string& output_dir);

    void set_template_dir(const std::string& dir);

private:
    std::string generate_html(const ThreatVerdict& verdict,
                               const std::string& filename);
    std::string severity_color(Severity sev);
    std::string verdict_color(Verdict v);

    std::string template_dir_;
};

}  // namespace shieldtier
