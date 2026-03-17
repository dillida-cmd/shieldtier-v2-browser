#include "export/export_manager.h"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <archive.h>
#include <archive_entry.h>

#include "common/json.h"
#include "export/defang.h"

namespace shieldtier {

namespace {

std::string current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &time);
#else
    gmtime_r(&time, &tm_buf);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string html_escape(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  result += "&amp;";  break;
            case '<':  result += "&lt;";   break;
            case '>':  result += "&gt;";   break;
            case '"':  result += "&quot;"; break;
            case '\'': result += "&#39;";  break;
            default:   result += c;        break;
        }
    }
    return result;
}

std::string verdict_label(Verdict v) {
    switch (v) {
        case Verdict::kClean:      return "CLEAN";
        case Verdict::kSuspicious: return "SUSPICIOUS";
        case Verdict::kMalicious:  return "MALICIOUS";
        case Verdict::kUnknown:    return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string severity_label(Severity s) {
    switch (s) {
        case Severity::kInfo:     return "Info";
        case Severity::kLow:      return "Low";
        case Severity::kMedium:   return "Medium";
        case Severity::kHigh:     return "High";
        case Severity::kCritical: return "Critical";
    }
    return "Info";
}

std::string engine_label(AnalysisEngine e) {
    switch (e) {
        case AnalysisEngine::kYara:         return "YARA";
        case AnalysisEngine::kFileAnalysis: return "File Analysis";
        case AnalysisEngine::kSandbox:      return "Sandbox";
        case AnalysisEngine::kAdvanced:     return "Advanced";
        case AnalysisEngine::kEnrichment:   return "Enrichment";
        case AnalysisEngine::kEmail:        return "Email";
        case AnalysisEngine::kContent:      return "Content";
        case AnalysisEngine::kLogAnalysis:  return "Log Analysis";
        case AnalysisEngine::kThreatFeed:   return "Threat Feed";
        case AnalysisEngine::kScoring:      return "Scoring";
        case AnalysisEngine::kVmSandbox:    return "VM Sandbox";
    }
    return "Unknown";
}

bool write_file(const std::string& path, const std::string& content) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    return ofs.good();
}

bool add_archive_entry(struct archive* a, const std::string& name,
                       const std::string& content) {
    struct archive_entry* entry = archive_entry_new();
    archive_entry_set_pathname(entry, name.c_str());
    archive_entry_set_size(entry, static_cast<la_int64_t>(content.size()));
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);

    if (archive_write_header(a, entry) != ARCHIVE_OK) {
        archive_entry_free(entry);
        return false;
    }

    la_ssize_t written = archive_write_data(
        a, content.data(), static_cast<size_t>(content.size()));
    archive_entry_free(entry);
    return written == static_cast<la_ssize_t>(content.size());
}

}  // namespace

ExportManager::ExportManager() = default;

void ExportManager::set_template_dir(const std::string& dir) {
    template_dir_ = dir;
}

Result<std::string> ExportManager::export_json(const ThreatVerdict& verdict,
                                                const std::string& filename) {
    // Defang individual fields before serialization to avoid corrupting JSON structure
    ThreatVerdict defanged_verdict = verdict;
    for (auto& f : defanged_verdict.findings) {
        f.title = Defang::defang_all(f.title);
        f.description = Defang::defang_all(f.description);
    }

    json j;
    j["filename"] = Defang::defang_all(filename);
    j["verdict"] = defanged_verdict;
    j["generated_at"] = current_timestamp();

    return j.dump(4);
}

Result<std::string> ExportManager::export_html(const ThreatVerdict& verdict,
                                                const std::string& filename) {
    return generate_html(verdict, filename);
}

Result<std::string> ExportManager::export_zip(const ThreatVerdict& verdict,
                                               const std::string& filename,
                                               const std::string& output_dir) {
    auto json_result = export_json(verdict, filename);
    if (!json_result.ok()) {
        return Error{json_result.error().message, "zip_json_fail"};
    }

    auto html_result = export_html(verdict, filename);
    if (!html_result.ok()) {
        return Error{html_result.error().message, "zip_html_fail"};
    }

    json metadata;
    metadata["filename"] = filename;
    metadata["verdict"] = verdict_label(verdict.verdict);
    metadata["threat_score"] = verdict.threat_score;
    metadata["risk_level"] = verdict.risk_level;
    metadata["generated_at"] = current_timestamp();
    metadata["report_version"] = "2.0";
    std::string metadata_str = metadata.dump(4);

    std::string zip_path = (std::filesystem::path(output_dir) / "shieldtier-report.zip").string();

    struct archive* a = archive_write_new();
    if (!a) {
        return Error{"Failed to create archive", "zip_init_fail"};
    }

    archive_write_set_format_zip(a);

    if (archive_write_open_filename(a, zip_path.c_str()) != ARCHIVE_OK) {
        std::string err = archive_error_string(a);
        archive_write_free(a);
        return Error{"Failed to open ZIP: " + err, "zip_open_fail"};
    }

    bool ok = true;
    ok = ok && add_archive_entry(a, "report.json", json_result.value());
    ok = ok && add_archive_entry(a, "report.html", html_result.value());
    ok = ok && add_archive_entry(a, "metadata.json", metadata_str);

    archive_write_close(a);
    archive_write_free(a);

    if (!ok) {
        std::filesystem::remove(zip_path);
        return Error{"Failed to write archive entries", "zip_write_fail"};
    }

    return zip_path;
}

std::string ExportManager::generate_html(const ThreatVerdict& verdict,
                                          const std::string& filename) {
    std::string vc = verdict_color(verdict.verdict);
    std::string defanged_filename = Defang::defang_all(filename);

    std::ostringstream html;
    html << R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShieldTier Report — )" << html_escape(defanged_filename) << R"(</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1e1e2e;color:#cdd6f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:2rem;line-height:1.6}
.container{max-width:960px;margin:0 auto}
h1{font-size:1.5rem;margin-bottom:0.25rem}
h2{font-size:1.2rem;margin:1.5rem 0 0.75rem;color:#89b4fa}
.header{border-bottom:1px solid #313244;padding-bottom:1.5rem;margin-bottom:1.5rem}
.badge{display:inline-block;padding:0.25rem 0.75rem;border-radius:4px;font-weight:700;font-size:0.9rem;color:#1e1e2e}
.meta{display:flex;gap:2rem;margin-top:0.75rem;flex-wrap:wrap}
.meta-item{font-size:0.9rem;color:#a6adc8}
.meta-item span{color:#cdd6f4;font-weight:600}
table{width:100%;border-collapse:collapse;margin-top:0.5rem}
th{text-align:left;padding:0.5rem 0.75rem;background:#313244;font-size:0.85rem;color:#a6adc8}
td{padding:0.5rem 0.75rem;border-bottom:1px solid #313244;font-size:0.9rem}
.sev{display:inline-block;padding:0.1rem 0.5rem;border-radius:3px;font-size:0.8rem;font-weight:600;color:#1e1e2e}
.mitre-list{display:flex;flex-wrap:wrap;gap:0.5rem;margin-top:0.5rem}
.mitre-tag{background:#313244;padding:0.2rem 0.6rem;border-radius:3px;font-size:0.85rem;font-family:monospace}
.footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #313244;font-size:0.8rem;color:#6c7086}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>)" << html_escape(defanged_filename) << R"(</h1>
<div style="margin-top:0.5rem">
<span class="badge" style="background:)" << vc << R"(">)" << verdict_label(verdict.verdict) << R"(</span>
</div>
<div class="meta">
<div class="meta-item">Threat Score: <span>)" << verdict.threat_score << R"(/100</span></div>
<div class="meta-item">Risk Level: <span>)" << html_escape(verdict.risk_level) << R"(</span></div>
<div class="meta-item">Confidence: <span>)" << std::fixed << std::setprecision(1)
     << (verdict.confidence * 100.0) << R"(%</span></div>
</div>
</div>
)";

    // Findings table
    if (!verdict.findings.empty()) {
        html << R"(<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Engine</th><th>Title</th><th>Description</th></tr></thead>
<tbody>
)";
        for (const auto& f : verdict.findings) {
            std::string sc = severity_color(f.severity);
            std::string defanged_title = Defang::defang_all(f.title);
            std::string defanged_desc = Defang::defang_all(f.description);

            html << "<tr>"
                 << "<td><span class=\"sev\" style=\"background:" << sc << "\">"
                 << severity_label(f.severity) << "</span></td>"
                 << "<td>" << html_escape(engine_label(f.engine)) << "</td>"
                 << "<td>" << html_escape(defanged_title) << "</td>"
                 << "<td>" << html_escape(defanged_desc) << "</td>"
                 << "</tr>\n";
        }
        html << "</tbody>\n</table>\n";
    }

    // MITRE techniques
    if (!verdict.mitre_techniques.empty()) {
        html << R"(<h2>MITRE ATT&amp;CK Techniques</h2>
<div class="mitre-list">
)";
        for (const auto& tech : verdict.mitre_techniques) {
            html << "<span class=\"mitre-tag\">"
                 << html_escape(Defang::defang_all(tech))
                 << "</span>\n";
        }
        html << "</div>\n";
    }

    html << "<div class=\"footer\">Generated by ShieldTier V2 at "
         << current_timestamp() << "</div>\n";
    html << "</div>\n</body>\n</html>\n";

    return html.str();
}

std::string ExportManager::severity_color(Severity sev) {
    switch (sev) {
        case Severity::kInfo:     return "#89b4fa";
        case Severity::kLow:      return "#a6e3a1";
        case Severity::kMedium:   return "#f9e2af";
        case Severity::kHigh:     return "#fab387";
        case Severity::kCritical: return "#f38ba8";
    }
    return "#6c7086";
}

std::string ExportManager::verdict_color(Verdict v) {
    switch (v) {
        case Verdict::kClean:      return "#a6e3a1";
        case Verdict::kSuspicious: return "#f9e2af";
        case Verdict::kMalicious:  return "#f38ba8";
        case Verdict::kUnknown:    return "#6c7086";
    }
    return "#6c7086";
}

}  // namespace shieldtier
