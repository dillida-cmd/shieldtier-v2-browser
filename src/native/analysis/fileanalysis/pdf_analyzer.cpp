#include "analysis/fileanalysis/pdf_analyzer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <regex>
#include <sstream>

#include "analysis/fileanalysis/file_analyzer.h"
#include "common/json.h"

namespace shieldtier {

namespace {

// Case-insensitive substring search within a byte range treated as latin1.
// Returns true if `needle` is found in [data, data+size).
bool find_in_content(const uint8_t* data, size_t size, const char* needle) {
    size_t needle_len = std::strlen(needle);
    if (needle_len == 0 || size < needle_len) return false;

    for (size_t i = 0; i <= size - needle_len; ++i) {
        if (std::memcmp(data + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

// Count occurrences of a pattern in the data.
size_t count_pattern(const uint8_t* data, size_t size, const char* needle) {
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

// Extract a string value from a PDF key like /Key (value) or /Key <hex>.
// Returns the first match found after the key.
std::string extract_paren_value(const uint8_t* data, size_t size,
                                 const char* key) {
    size_t key_len = std::strlen(key);
    if (key_len == 0 || size < key_len + 2) return "";

    for (size_t i = 0; i <= size - key_len - 2; ++i) {
        if (std::memcmp(data + i, key, key_len) == 0) {
            // Skip whitespace after key
            size_t j = i + key_len;
            while (j < size && (data[j] == ' ' || data[j] == '\r' ||
                                data[j] == '\n' || data[j] == '\t')) {
                j++;
            }
            if (j < size && data[j] == '(') {
                // Extract until closing paren (handling one level of nesting)
                j++;
                std::string result;
                int depth = 1;
                while (j < size && depth > 0) {
                    if (data[j] == '(' && data[j - 1] != '\\') {
                        depth++;
                    } else if (data[j] == ')' && data[j - 1] != '\\') {
                        depth--;
                        if (depth == 0) break;
                    }
                    result += static_cast<char>(data[j]);
                    j++;
                }
                return result;
            }
        }
    }
    return "";
}

}  // namespace

PdfInfo PdfAnalyzer::parse_structure(const uint8_t* data, size_t size) {
    PdfInfo info{};
    info.page_count = 0;
    info.object_count = 0;
    info.has_javascript = false;
    info.has_open_action = false;
    info.has_additional_actions = false;
    info.has_launch_actions = false;
    info.has_embedded_files = false;
    info.has_submit_form = false;
    info.has_encryption = false;
    info.entropy = 0.0;

    if (size < 5) return info;

    // Extract version from %PDF-X.Y header
    if (data[0] == '%' && data[1] == 'P' && data[2] == 'D' &&
        data[3] == 'F' && data[4] == '-') {
        size_t end = 5;
        while (end < size && end < 12 && data[end] != '\r' &&
               data[end] != '\n') {
            end++;
        }
        info.version =
            std::string(reinterpret_cast<const char*>(data + 5), end - 5);
    }

    // Count PDF objects (N N obj pattern)
    // Use a simple scan for " obj" preceded by digits
    for (size_t i = 3; i < size - 3; ++i) {
        if (data[i] == ' ' && data[i + 1] == 'o' && data[i + 2] == 'b' &&
            data[i + 3] == 'j') {
            // Check that preceding chars contain digits and space
            if (i >= 3 && data[i - 1] >= '0' && data[i - 1] <= '9') {
                info.object_count++;
            }
        }
    }

    // Count pages: /Type /Page (not /Pages)
    // Look for "/Type" followed by whitespace and "/Page" but not "/Pages"
    for (size_t i = 0; i + 10 < size; ++i) {
        if (std::memcmp(data + i, "/Type", 5) == 0) {
            size_t j = i + 5;
            // Skip whitespace
            while (j < size && (data[j] == ' ' || data[j] == '\r' ||
                                data[j] == '\n' || data[j] == '\t')) {
                j++;
            }
            if (j + 5 <= size && std::memcmp(data + j, "/Page", 5) == 0) {
                // Make sure it's /Page and not /Pages
                if (j + 5 >= size || data[j + 5] != 's') {
                    info.page_count++;
                }
            }
        }
    }

    // Fallback: if no /Type /Page found, try /Count in catalog
    if (info.page_count == 0) {
        for (size_t i = 0; i + 6 < size; ++i) {
            if (std::memcmp(data + i, "/Count", 6) == 0) {
                size_t j = i + 6;
                while (j < size && (data[j] == ' ' || data[j] == '\r' ||
                                    data[j] == '\n' || data[j] == '\t')) {
                    j++;
                }
                size_t num_start = j;
                while (j < size && data[j] >= '0' && data[j] <= '9') {
                    j++;
                }
                if (j > num_start) {
                    std::string num_str(
                        reinterpret_cast<const char*>(data + num_start),
                        j - num_start);
                    try {
                        size_t count = std::stoul(num_str);
                        if (count > info.page_count) {
                            info.page_count = count;
                        }
                    } catch (...) {
                    }
                }
            }
        }
    }

    // Detect JavaScript: /JS or /JavaScript
    info.has_javascript =
        find_in_content(data, size, "/JS ") ||
        find_in_content(data, size, "/JS\r") ||
        find_in_content(data, size, "/JS\n") ||
        find_in_content(data, size, "/JS(") ||
        find_in_content(data, size, "/JavaScript") ||
        find_in_content(data, size, "/S /JavaScript");

    // Detect auto-execution actions
    info.has_open_action = find_in_content(data, size, "/OpenAction");
    info.has_additional_actions =
        find_in_content(data, size, "/AA ") ||
        find_in_content(data, size, "/AA\r") ||
        find_in_content(data, size, "/AA\n") ||
        find_in_content(data, size, "/AA<");

    // Detect Launch actions
    info.has_launch_actions = find_in_content(data, size, "/Launch");

    // Detect embedded files
    info.has_embedded_files = find_in_content(data, size, "/EmbeddedFile");

    // Detect form submission
    info.has_submit_form = find_in_content(data, size, "/SubmitForm");

    // Detect encryption
    info.has_encryption = find_in_content(data, size, "/Encrypt");

    // Extract URIs: /URI (http://...)
    {
        const std::regex uri_re("/URI\\s*\\(([^)]+)\\)");
        std::string content(reinterpret_cast<const char*>(data),
                            std::min(size, size_t(1024 * 1024)));
        std::sregex_iterator it(content.begin(), content.end(), uri_re);
        std::sregex_iterator end;
        for (; it != end; ++it) {
            info.uris.push_back((*it)[1].str());
            if (info.uris.size() >= 100) break;  // Limit URI extraction
        }
    }

    // Calculate entropy
    info.entropy = FileAnalyzer::calculate_entropy(data, size);

    return info;
}

std::vector<Finding> PdfAnalyzer::generate_findings(const PdfInfo& info) {
    std::vector<Finding> findings;

    if (info.has_javascript) {
        findings.push_back({
            "Embedded JavaScript detected",
            "PDF contains /JavaScript or /JS actions — common malware "
            "delivery vector",
            Severity::kCritical,
            AnalysisEngine::kFileAnalysis,
            {{"has_javascript", true}},
        });
    }

    if (info.has_open_action) {
        findings.push_back({
            "OpenAction detected",
            "/OpenAction present — code or action executes when PDF is opened",
            Severity::kHigh,
            AnalysisEngine::kFileAnalysis,
            {{"has_open_action", true}},
        });
    }

    if (info.has_additional_actions) {
        findings.push_back({
            "Additional Actions (AA) detected",
            "/AA dictionary present — automatic action triggers on various "
            "events",
            Severity::kHigh,
            AnalysisEngine::kFileAnalysis,
            {{"has_additional_actions", true}},
        });
    }

    if (info.has_launch_actions) {
        findings.push_back({
            "Launch action detected",
            "/Launch action can execute external programs — high risk of "
            "malicious payload execution",
            Severity::kHigh,
            AnalysisEngine::kFileAnalysis,
            {{"has_launch_actions", true}},
        });
    }

    if (info.has_embedded_files) {
        findings.push_back({
            "Embedded file detected",
            "PDF contains /EmbeddedFile streams — may contain hidden "
            "payloads",
            Severity::kMedium,
            AnalysisEngine::kFileAnalysis,
            {{"has_embedded_files", true}},
        });
    }

    if (info.has_submit_form) {
        findings.push_back({
            "Form submission action detected",
            "/SubmitForm action present — may exfiltrate form data to "
            "external server",
            Severity::kHigh,
            AnalysisEngine::kFileAnalysis,
            {{"has_submit_form", true}},
        });
    }

    if (info.has_encryption) {
        findings.push_back({
            "PDF encryption detected",
            "/Encrypt dictionary present — encrypted PDF may hide malicious "
            "content from scanners",
            Severity::kMedium,
            AnalysisEngine::kFileAnalysis,
            {{"has_encryption", true}},
        });
    }

    if (!info.uris.empty()) {
        json uri_list = json::array();
        for (const auto& uri : info.uris) {
            uri_list.push_back(uri);
        }
        findings.push_back({
            "URIs found in PDF",
            std::to_string(info.uris.size()) +
                " URI(s) extracted from /URI actions",
            Severity::kInfo,
            AnalysisEngine::kFileAnalysis,
            {{"count", info.uris.size()}, {"uris", uri_list}},
        });
    }

    if (info.entropy > 7.2) {
        findings.push_back({
            "High PDF entropy",
            "PDF file entropy is " + std::to_string(info.entropy) +
                " (possible obfuscation or embedded encrypted content)",
            Severity::kMedium,
            AnalysisEngine::kFileAnalysis,
            {{"entropy", info.entropy}},
        });
    }

    return findings;
}

Result<AnalysisEngineResult> PdfAnalyzer::analyze(const FileBuffer& file) {
    auto start = std::chrono::steady_clock::now();

    if (file.size() < 5 || file.ptr()[0] != '%' || file.ptr()[1] != 'P' ||
        file.ptr()[2] != 'D' || file.ptr()[3] != 'F') {
        return Error("Not a valid PDF file: missing %PDF header");
    }

    PdfInfo info = parse_structure(file.ptr(), file.size());

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kFileAnalysis;
    result.success = true;

    result.findings = generate_findings(info);

    result.raw_output["pdf"] = {
        {"version", info.version},
        {"page_count", info.page_count},
        {"object_count", info.object_count},
        {"has_javascript", info.has_javascript},
        {"has_open_action", info.has_open_action},
        {"has_additional_actions", info.has_additional_actions},
        {"has_launch_actions", info.has_launch_actions},
        {"has_embedded_files", info.has_embedded_files},
        {"has_submit_form", info.has_submit_form},
        {"has_encryption", info.has_encryption},
        {"entropy", info.entropy},
        {"uri_count", info.uris.size()},
    };

    auto end = std::chrono::steady_clock::now();
    result.duration_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    return result;
}

}  // namespace shieldtier
