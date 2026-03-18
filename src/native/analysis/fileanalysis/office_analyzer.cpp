#include "analysis/fileanalysis/office_analyzer.h"

#include <algorithm>
#include <chrono>
#include <cstring>

#include "common/json.h"

namespace shieldtier {

namespace {

// OLE2 Compound File Binary Format header signature
constexpr uint8_t kOle2Signature[] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1,
                                       0x1A, 0xE1};

// ZIP PK signature
constexpr uint8_t kPkSignature[] = {0x50, 0x4B, 0x03, 0x04};

bool find_bytes(const uint8_t* data, size_t size, const char* needle) {
    size_t needle_len = std::strlen(needle);
    if (needle_len == 0 || size < needle_len) return false;
    for (size_t i = 0; i <= size - needle_len; ++i) {
        if (std::memcmp(data + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

size_t count_bytes(const uint8_t* data, size_t size, const char* needle) {
    size_t needle_len = std::strlen(needle);
    if (needle_len == 0 || size < needle_len) return 0;
    size_t count = 0;
    for (size_t i = 0; i <= size - needle_len; ++i) {
        if (std::memcmp(data + i, needle, needle_len) == 0) {
            count++;
        }
    }
    return count;
}

std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

}  // namespace

OfficeInfo OfficeAnalyzer::analyze_ooxml(const uint8_t* data, size_t size) {
    OfficeInfo info{};
    info.format = "ooxml";
    info.has_macros = false;
    info.has_external_links = false;
    info.has_activex = false;
    info.has_embedded_objects = false;
    info.has_dde = false;
    info.external_link_count = 0;
    info.embedded_object_count = 0;

    // OOXML is a ZIP containing XML files.
    // Scan the raw bytes for known patterns (filenames and XML content).

    // Check for vbaProject.bin (VBA macros)
    if (find_bytes(data, size, "vbaProject.bin")) {
        info.has_macros = true;
    }

    // Check for macro-enabled content types
    if (find_bytes(data, size, "vnd.ms-excel.sheet.macroEnabled") ||
        find_bytes(data, size, "vnd.ms-word.document.macroEnabled") ||
        find_bytes(data, size, "vnd.ms-powerpoint.presentation.macroEnabled")) {
        info.has_macros = true;
    }

    // Check for external relationships (Target="http" with TargetMode="External")
    info.external_link_count = count_bytes(data, size, "TargetMode=\"External\"");
    if (info.external_link_count > 0) {
        info.has_external_links = true;
    }

    // Check for ActiveX controls
    if (find_bytes(data, size, "activeX") ||
        find_bytes(data, size, "ActiveX")) {
        info.has_activex = true;
    }

    // Check for embedded OLE objects
    info.embedded_object_count = count_bytes(data, size, "oleObject");
    if (info.embedded_object_count > 0) {
        info.has_embedded_objects = true;
    }

    // Check for DDE (Dynamic Data Exchange) fields
    if (find_bytes(data, size, "DDE") ||
        find_bytes(data, size, "DDEAUTO") ||
        find_bytes(data, size, "ddeLink")) {
        info.has_dde = true;
    }

    // Extract content types for metadata
    // [Content_Types].xml lists all content types in the package.
    // Look for ContentType= patterns
    std::string content(reinterpret_cast<const char*>(data),
                        std::min(size, size_t(64 * 1024)));
    size_t pos = 0;
    while (pos < content.size() && info.content_types.size() < 50) {
        auto ct = content.find("ContentType=\"", pos);
        if (ct == std::string::npos) break;
        auto start = ct + 13;
        auto end = content.find('"', start);
        if (end == std::string::npos) break;
        std::string ct_val = content.substr(start, end - start);
        if (std::find(info.content_types.begin(), info.content_types.end(),
                      ct_val) == info.content_types.end()) {
            info.content_types.push_back(ct_val);
        }
        pos = end + 1;
    }

    // Check for auto-execution triggers in VBA
    if (find_bytes(data, size, "AutoOpen") ||
        find_bytes(data, size, "Auto_Open") ||
        find_bytes(data, size, "Document_Open") ||
        find_bytes(data, size, "Workbook_Open")) {
        info.auto_exec_triggers.push_back("AutoOpen/Document_Open");
    }
    if (find_bytes(data, size, "AutoClose") ||
        find_bytes(data, size, "Document_Close")) {
        info.auto_exec_triggers.push_back("AutoClose/Document_Close");
    }
    if (find_bytes(data, size, "AutoExec") ||
        find_bytes(data, size, "Auto_Exec")) {
        info.auto_exec_triggers.push_back("AutoExec");
    }

    return info;
}

OfficeInfo OfficeAnalyzer::analyze_ole2(const uint8_t* data, size_t size) {
    OfficeInfo info{};
    info.format = "ole2";
    info.has_macros = false;
    info.has_external_links = false;
    info.has_activex = false;
    info.has_embedded_objects = false;
    info.has_dde = false;
    info.external_link_count = 0;
    info.embedded_object_count = 0;

    // OLE2 files are Compound File Binary Format.
    // Scan for VBA macro indicators without full CFBF parsing.

    // VBA stream markers: "Attribut" (note: lowercase 'e' often missing in VBA
    // stream header) and "VBA" directory entries
    if (find_bytes(data, size, "Attribut") ||
        find_bytes(data, size, "_VBA_PROJECT") ||
        find_bytes(data, size, "VBA")) {
        info.has_macros = true;
    }

    // Check for "Macros" storage name in directory entries
    // In OLE2, directory entry names are UTF-16LE
    // "Macros" in UTF-16LE: M\0a\0c\0r\0o\0s\0
    const uint8_t macros_utf16[] = {'M', 0, 'a', 0, 'c', 0,
                                     'r', 0, 'o', 0, 's', 0};
    for (size_t i = 0; i + sizeof(macros_utf16) <= size; ++i) {
        if (std::memcmp(data + i, macros_utf16, sizeof(macros_utf16)) == 0) {
            info.has_macros = true;
            break;
        }
    }

    // Check for embedded objects
    // OLE1 object markers
    if (find_bytes(data, size, "\x01Ole") ||
        find_bytes(data, size, "ObjectPool") ||
        find_bytes(data, size, "\x01CompObj")) {
        info.has_embedded_objects = true;
    }

    // Check for external links
    if (find_bytes(data, size, "LINK") ||
        find_bytes(data, size, "HyperLink")) {
        info.has_external_links = true;
    }

    // Check for DDE
    if (find_bytes(data, size, "DDE") ||
        find_bytes(data, size, "DDEAUTO")) {
        info.has_dde = true;
    }

    // Auto-exec triggers
    if (find_bytes(data, size, "AutoOpen") ||
        find_bytes(data, size, "Auto_Open") ||
        find_bytes(data, size, "Document_Open") ||
        find_bytes(data, size, "Workbook_Open")) {
        info.auto_exec_triggers.push_back("AutoOpen/Document_Open");
    }
    if (find_bytes(data, size, "AutoClose") ||
        find_bytes(data, size, "Document_Close")) {
        info.auto_exec_triggers.push_back("AutoClose/Document_Close");
    }
    if (find_bytes(data, size, "AutoExec")) {
        info.auto_exec_triggers.push_back("AutoExec");
    }

    return info;
}

std::vector<Finding> OfficeAnalyzer::generate_findings(
    const OfficeInfo& info) {
    std::vector<Finding> findings;

    if (info.has_macros) {
        Severity sev = Severity::kHigh;
        std::string desc =
            "Document contains VBA macros — common malware delivery method";
        if (!info.auto_exec_triggers.empty()) {
            sev = Severity::kCritical;
            desc += ". Auto-execution triggers detected: ";
            for (size_t i = 0; i < info.auto_exec_triggers.size(); ++i) {
                if (i > 0) desc += ", ";
                desc += info.auto_exec_triggers[i];
            }
        }
        json meta = {{"has_macros", true}, {"format", info.format}};
        if (!info.auto_exec_triggers.empty()) {
            json triggers = json::array();
            for (const auto& t : info.auto_exec_triggers) {
                triggers.push_back(t);
            }
            meta["auto_exec_triggers"] = triggers;
        }
        findings.push_back({
            "VBA macros detected",
            desc,
            sev,
            AnalysisEngine::kFileAnalysis,
            meta,
        });
    }

    if (info.has_external_links) {
        findings.push_back({
            "External data connections",
            "Document contains " +
                std::to_string(info.external_link_count) +
                " external relationship(s) — may fetch remote content",
            Severity::kMedium,
            AnalysisEngine::kFileAnalysis,
            {{"external_link_count", info.external_link_count}},
        });
    }

    if (info.has_activex) {
        findings.push_back({
            "ActiveX controls detected",
            "Document contains ActiveX controls — can execute arbitrary code",
            Severity::kHigh,
            AnalysisEngine::kFileAnalysis,
            {{"has_activex", true}},
        });
    }

    if (info.has_embedded_objects) {
        findings.push_back({
            "Embedded OLE objects",
            "Document contains " +
                std::to_string(info.embedded_object_count) +
                " embedded OLE object(s) — may contain hidden payloads",
            Severity::kMedium,
            AnalysisEngine::kFileAnalysis,
            {{"embedded_object_count", info.embedded_object_count}},
        });
    }

    if (info.has_dde) {
        findings.push_back({
            "DDE (Dynamic Data Exchange) detected",
            "Document uses DDE/DDEAUTO — can execute commands without macros",
            Severity::kHigh,
            AnalysisEngine::kFileAnalysis,
            {{"has_dde", true}},
        });
    }

    return findings;
}

Result<AnalysisEngineResult> OfficeAnalyzer::analyze(const FileBuffer& file) {
    auto start = std::chrono::steady_clock::now();

    if (file.size() < 8) {
        return Error("File too small to be an Office document");
    }

    OfficeInfo info;
    bool is_ole2 = (file.size() >= 8 &&
                    std::memcmp(file.ptr(), kOle2Signature, 8) == 0);
    bool is_ooxml = (file.size() >= 4 &&
                     std::memcmp(file.ptr(), kPkSignature, 4) == 0);

    if (is_ole2) {
        info = analyze_ole2(file.ptr(), file.size());
    } else if (is_ooxml) {
        info = analyze_ooxml(file.ptr(), file.size());
    } else {
        return Error("Not a recognized Office file format");
    }

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kFileAnalysis;
    result.success = true;

    result.findings = generate_findings(info);

    json content_types_json = json::array();
    for (const auto& ct : info.content_types) {
        content_types_json.push_back(ct);
    }

    result.raw_output["office"] = {
        {"format", info.format},
        {"has_macros", info.has_macros},
        {"has_external_links", info.has_external_links},
        {"has_activex", info.has_activex},
        {"has_embedded_objects", info.has_embedded_objects},
        {"has_dde", info.has_dde},
        {"external_link_count", info.external_link_count},
        {"embedded_object_count", info.embedded_object_count},
        {"content_types", content_types_json},
    };

    auto end = std::chrono::steady_clock::now();
    result.duration_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    return result;
}

}  // namespace shieldtier
