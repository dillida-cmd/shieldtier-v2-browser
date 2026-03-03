#include "analysis/content/content_analyzer.h"

#include <algorithm>
#include <chrono>
#include <regex>
#include <string>

namespace shieldtier {

namespace {

constexpr size_t kMaxContentSize = 16 * 1024 * 1024;

bool contains_ci(const std::string& haystack, const std::string& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        }
    );
    return it != haystack.end();
}

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

// Count occurrences of a substring (case-insensitive)
int count_occurrences_ci(const std::string& haystack, const std::string& needle) {
    std::string h = to_lower(haystack);
    std::string n = to_lower(needle);
    int count = 0;
    size_t pos = 0;
    while ((pos = h.find(n, pos)) != std::string::npos) {
        ++count;
        pos += n.size();
    }
    return count;
}

// Pre-compiled regexes for performance
const std::regex& eval_regex() {
    static const std::regex re(R"(\beval\s*\()", std::regex::icase);
    return re;
}

const std::regex& new_function_regex() {
    static const std::regex re(R"(new\s+Function\s*\()", std::regex::icase);
    return re;
}

const std::regex& document_write_regex() {
    static const std::regex re(R"(document\.write\w*\s*\()", std::regex::icase);
    return re;
}

const std::regex& from_char_code_regex() {
    static const std::regex re(
        R"(String\.fromCharCode\s*\([^)]{20,}\))", std::regex::icase);
    return re;
}

const std::regex& nested_atob_regex() {
    static const std::regex re(R"(atob\s*\(\s*atob\s*\()", std::regex::icase);
    return re;
}

const std::regex& meta_refresh_regex() {
    static const std::regex re(
        R"(<meta[^>]+http-equiv\s*=\s*"?refresh"?[^>]+content\s*=\s*"[^"]*url)",
        std::regex::icase);
    return re;
}

const std::regex& window_location_regex() {
    static const std::regex re(
        R"((window|document)\.location\s*(\.href\s*)?=)", std::regex::icase);
    return re;
}

const std::regex& send_beacon_regex() {
    static const std::regex re(
        R"(navigator\.sendBeacon\s*\()", std::regex::icase);
    return re;
}

const std::regex& tracking_pixel_regex() {
    static const std::regex re(
        R"(<img[^>]+(?:width|height)\s*=\s*"?1"?[^>]+(?:width|height)\s*=\s*"?1"?)",
        std::regex::icase);
    return re;
}

const std::regex& external_script_regex() {
    static const std::regex re(
        R"(<script[^>]+src\s*=\s*"(https?://[^"]+)")", std::regex::icase);
    return re;
}

const std::regex& hidden_iframe_regex() {
    static const std::regex re(
        R"(<iframe[^>]+(?:display\s*:\s*none|width\s*=\s*"?0"?|height\s*=\s*"?0"?))",
        std::regex::icase);
    return re;
}

const std::regex& form_password_regex() {
    static const std::regex re(
        R"(<form[^>]+action\s*=\s*"(https?://[^"]+)"[\s\S]{0,2000}?<input[^>]+type\s*=\s*"password")",
        std::regex::icase);
    return re;
}

const std::regex& base64_in_script_regex() {
    static const std::regex re(
        R"(<script[^>]*>[\s\S]*?[A-Za-z0-9+/]{500,}={0,2}[\s\S]*?</script>)",
        std::regex::icase);
    return re;
}

const std::regex& crypto_miner_regex() {
    static const std::regex re(
        R"(coinhive|coinimp|cryptonight|miner\.start\s*\(|cryptoloot|coin-hive)",
        std::regex::icase);
    return re;
}

const std::regex& char_at_chain_regex() {
    static const std::regex re(
        R"(\.charAt\s*\([^)]*\)\s*(?:\+\s*\S+\.charAt\s*\([^)]*\)\s*){3,})");
    return re;
}

const std::regex& from_char_code_many_regex() {
    static const std::regex re(
        R"(String\.fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){10,}\))");
    return re;
}

const std::regex& websocket_regex() {
    static const std::regex re(
        R"(new\s+WebSocket\s*\(\s*["']wss?://[^"']*:\d+)",
        std::regex::icase);
    return re;
}

const std::regex& cookie_exfil_regex() {
    static const std::regex re(
        R"(document\.cookie)", std::regex::icase);
    return re;
}

const std::regex& hex_string_regex() {
    static const std::regex re(
        R"(["'][0-9a-fA-F\\x]{1000,}["'])");
    return re;
}

}  // namespace

ContentAnalyzer::ContentAnalyzer() = default;

Result<AnalysisEngineResult> ContentAnalyzer::analyze(const FileBuffer& file) {
    auto start = std::chrono::steady_clock::now();

    if (file.size() == 0) {
        AnalysisEngineResult result;
        result.engine = AnalysisEngine::kContent;
        result.success = true;
        result.duration_ms = 0;
        return result;
    }

    size_t scan_size = std::min(file.size(), kMaxContentSize);
    std::string content(reinterpret_cast<const char*>(file.ptr()), scan_size);

    std::vector<Finding> findings;

    auto html_findings = analyze_html(content);
    findings.insert(findings.end(), html_findings.begin(), html_findings.end());

    auto js_findings = analyze_javascript(content);
    findings.insert(findings.end(), js_findings.begin(), js_findings.end());

    auto end = std::chrono::steady_clock::now();
    double duration_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kContent;
    result.success = true;
    result.findings = std::move(findings);
    result.duration_ms = duration_ms;
    result.raw_output = {
        {"content_length", scan_size},
        {"filename", file.filename},
        {"mime_type", file.mime_type},
        {"iframe_count", count_iframes(content)},
        {"has_phishing_form", detect_phishing_form(content)},
        {"has_drive_by_download", detect_drive_by_download(content)},
        {"has_obfuscated_js", detect_obfuscated_js(content)},
    };

    return result;
}

std::vector<Finding> ContentAnalyzer::analyze_html(const std::string& content) {
    std::vector<Finding> findings;

    if (std::regex_search(content, eval_regex())) {
        findings.push_back({
            "Content: eval() Usage Detected",
            "HTML content uses eval() for dynamic code execution — common in obfuscated malware",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "eval()"}},
        });
    }

    if (std::regex_search(content, new_function_regex())) {
        findings.push_back({
            "Content: new Function() Constructor",
            "Dynamic code generation via new Function() — used to evade static analysis",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "new Function()"}},
        });
    }

    if (std::regex_search(content, document_write_regex())) {
        findings.push_back({
            "Content: document.write() Usage",
            "document.write() can inject arbitrary content into the page — used in injection attacks",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "document.write()"}},
        });
    }

    if (std::regex_search(content, from_char_code_regex())) {
        findings.push_back({
            "Content: String.fromCharCode Chain",
            "String.fromCharCode with many arguments — likely obfuscated string construction",
            Severity::kHigh,
            AnalysisEngine::kContent,
            {{"pattern", "String.fromCharCode chain"}},
        });
    }

    if (std::regex_search(content, nested_atob_regex())) {
        findings.push_back({
            "Content: Nested Base64 Decoding",
            "Multiple layers of atob() decoding — strong indicator of payload obfuscation",
            Severity::kHigh,
            AnalysisEngine::kContent,
            {{"pattern", "nested atob()"}},
        });
    }

    // Hidden iframes
    if (std::regex_search(content, hidden_iframe_regex())) {
        findings.push_back({
            "Content: Hidden Iframe Detected",
            "Hidden iframe (display:none or 0x0 dimensions) — commonly used for drive-by downloads or clickjacking",
            Severity::kHigh,
            AnalysisEngine::kContent,
            {{"mitre_technique", "T1189"}},
        });
    }

    // Credential harvesting form
    if (detect_phishing_form(content)) {
        findings.push_back({
            "Content: Credential Harvesting Form",
            "Page contains a login form with password field posting to an external URL",
            Severity::kCritical,
            AnalysisEngine::kContent,
            {{"mitre_technique", "T1056.003"}},
        });
    }

    // Crypto mining
    if (std::regex_search(content, crypto_miner_regex())) {
        findings.push_back({
            "Content: Cryptocurrency Miner Detected",
            "Page contains references to browser-based cryptocurrency mining scripts (CoinHive/CoinImp/CryptoNight)",
            Severity::kHigh,
            AnalysisEngine::kContent,
            {{"mitre_technique", "T1496"}},
        });
    }

    // Suspicious redirects
    if (std::regex_search(content, meta_refresh_regex())) {
        findings.push_back({
            "Content: Meta Refresh Redirect",
            "Page uses meta refresh tag to redirect — may be used for phishing or drive-by attacks",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "meta refresh"}},
        });
    }

    if (std::regex_search(content, window_location_regex())) {
        findings.push_back({
            "Content: JavaScript Location Redirect",
            "JavaScript modifies window/document location — potential redirect to malicious site",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "window.location assignment"}},
        });
    }

    // Data exfiltration patterns
    if (std::regex_search(content, send_beacon_regex())) {
        findings.push_back({
            "Content: navigator.sendBeacon() Usage",
            "Page uses sendBeacon for background data transmission — may indicate data exfiltration",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "navigator.sendBeacon()"}, {"mitre_technique", "T1041"}},
        });
    }

    // Tracking pixels
    if (std::regex_search(content, tracking_pixel_regex())) {
        findings.push_back({
            "Content: Tracking Pixel Detected",
            "Page contains a 1x1 image commonly used for tracking user activity",
            Severity::kLow,
            AnalysisEngine::kContent,
            {{"pattern", "1x1 tracking pixel"}},
        });
    }

    // External scripts
    std::smatch ext_script_match;
    std::string search_content = content;
    int external_script_count = 0;
    while (std::regex_search(search_content, ext_script_match, external_script_regex()) &&
           external_script_count < 50) {
        ++external_script_count;
        search_content = ext_script_match.suffix().str();
    }
    if (external_script_count > 0) {
        findings.push_back({
            "Content: External Script References",
            "Page loads " + std::to_string(external_script_count) +
                " external script(s) from remote origins",
            external_script_count > 10 ? Severity::kMedium : Severity::kLow,
            AnalysisEngine::kContent,
            {{"external_script_count", external_script_count}},
        });
    }

    // Excessive iframes
    int iframe_count = count_iframes(content);
    if (iframe_count > 5) {
        findings.push_back({
            "Content: Excessive Iframes",
            "Page contains " + std::to_string(iframe_count) +
                " iframes — may indicate exploit kit or click fraud",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"iframe_count", iframe_count}},
        });
    }

    // Large base64 payload inside <script> tags
    if (std::regex_search(content, base64_in_script_regex())) {
        findings.push_back({
            "Content: Large Base64 Payload in Script",
            "Script tag contains a base64-encoded payload exceeding 500 characters — likely embedded binary or obfuscated code",
            Severity::kHigh,
            AnalysisEngine::kContent,
            {{"mitre_technique", "T1027"}},
        });
    }

    // Drive-by download triggers
    if (detect_drive_by_download(content)) {
        findings.push_back({
            "Content: Drive-By Download Trigger",
            "Page contains mechanisms for automatic file download without user interaction",
            Severity::kCritical,
            AnalysisEngine::kContent,
            {{"mitre_technique", "T1189"}},
        });
    }

    // Hidden divs containing scripts
    static const std::regex hidden_div_script_re(
        R"(<div[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden)[^>]*>[\s\S]{0,2000}?<script)",
        std::regex::icase);
    if (std::regex_search(content, hidden_div_script_re)) {
        findings.push_back({
            "Content: Hidden Div with Embedded Script",
            "Hidden HTML element contains a script tag — possible hidden malicious payload",
            Severity::kHigh,
            AnalysisEngine::kContent,
            {{"mitre_technique", "T1027"}},
        });
    }

    return findings;
}

std::vector<Finding> ContentAnalyzer::analyze_javascript(const std::string& content) {
    std::vector<Finding> findings;

    // Overall obfuscation check
    if (detect_obfuscated_js(content)) {
        findings.push_back({
            "Content: Heavily Obfuscated JavaScript",
            "Multiple obfuscation indicators detected — code is likely intentionally obscured to hide malicious behavior",
            Severity::kHigh,
            AnalysisEngine::kContent,
            {{"mitre_technique", "T1027"}},
        });
    }

    // charAt/charCodeAt chains
    if (std::regex_search(content, char_at_chain_regex())) {
        findings.push_back({
            "Content: charAt/charCodeAt Chain Obfuscation",
            "JavaScript uses chained charAt() calls for character-by-character string construction — typical of obfuscated payloads",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "charAt chain"}},
        });
    }

    // String.fromCharCode with many arguments
    if (std::regex_search(content, from_char_code_many_regex())) {
        findings.push_back({
            "Content: Mass String.fromCharCode Construction",
            "String.fromCharCode called with 10+ numeric arguments — likely constructing a hidden string payload",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "String.fromCharCode mass call"}},
        });
    }

    // unescape() usage
    if (contains_ci(content, "unescape(")) {
        findings.push_back({
            "Content: unescape() Function Usage",
            "JavaScript uses deprecated unescape() — commonly seen in legacy exploit code and obfuscated malware",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "unescape()"}},
        });
    }

    // Long hex or encoded strings
    if (std::regex_search(content, hex_string_regex())) {
        findings.push_back({
            "Content: Long Hex/Encoded String",
            "JavaScript contains a string literal with 1000+ hex or encoded characters — likely an embedded payload",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "long hex string"}},
        });
    }

    // WebSocket to suspicious ports
    if (std::regex_search(content, websocket_regex())) {
        findings.push_back({
            "Content: WebSocket Connection to Specific Port",
            "JavaScript opens a WebSocket connection to a numbered port — may indicate C2 communication",
            Severity::kMedium,
            AnalysisEngine::kContent,
            {{"pattern", "WebSocket to port"}, {"mitre_technique", "T1071.001"}},
        });
    }

    // document.cookie access + external requests (exfiltration pattern)
    if (std::regex_search(content, cookie_exfil_regex())) {
        bool has_external_request =
            contains_ci(content, "fetch(") ||
            contains_ci(content, "XMLHttpRequest") ||
            contains_ci(content, "$.ajax") ||
            contains_ci(content, "$.get(") ||
            contains_ci(content, "$.post(") ||
            std::regex_search(content, send_beacon_regex());

        if (has_external_request) {
            findings.push_back({
                "Content: Cookie Access with External Request",
                "JavaScript accesses document.cookie and makes external HTTP requests — potential cookie exfiltration",
                Severity::kHigh,
                AnalysisEngine::kContent,
                {{"mitre_technique", "T1539"}},
            });
        }
    }

    return findings;
}

bool ContentAnalyzer::detect_phishing_form(const std::string& html) {
    return std::regex_search(html, form_password_regex());
}

bool ContentAnalyzer::detect_drive_by_download(const std::string& html) {
    std::string lower = to_lower(html);

    // Hidden iframe with download-related src
    if (std::regex_search(html, hidden_iframe_regex())) {
        // Check if any iframe src contains download-suggestive patterns
        static const std::regex iframe_src_re(
            R"(<iframe[^>]+src\s*=\s*"([^"]+)")", std::regex::icase);
        std::smatch m;
        std::string search = html;
        while (std::regex_search(search, m, iframe_src_re)) {
            std::string src = to_lower(m[1].str());
            if (src.find(".exe") != std::string::npos ||
                src.find(".msi") != std::string::npos ||
                src.find("download") != std::string::npos) {
                return true;
            }
            search = m.suffix().str();
        }
    }

    // JS-triggered auto-click on download links
    if (contains_ci(html, ".click()") &&
        (contains_ci(html, "download") || contains_ci(html, "blob:"))) {
        return true;
    }

    // Auto-download via anchor with download attribute and JS click
    static const std::regex auto_download_re(
        R"(<a[^>]+download[^>]*>[\s\S]{0,500}?\.click\s*\(\))",
        std::regex::icase);
    if (std::regex_search(html, auto_download_re)) {
        return true;
    }

    return false;
}

bool ContentAnalyzer::detect_obfuscated_js(const std::string& js) {
    int indicators = 0;

    if (std::regex_search(js, char_at_chain_regex())) ++indicators;
    if (std::regex_search(js, from_char_code_many_regex())) ++indicators;
    if (contains_ci(js, "unescape(")) ++indicators;
    if (std::regex_search(js, eval_regex())) ++indicators;
    if (std::regex_search(js, nested_atob_regex())) ++indicators;
    if (std::regex_search(js, hex_string_regex())) ++indicators;

    // Deeply nested function calls: 5+ levels of nesting
    int max_depth = 0;
    int depth = 0;
    for (char c : js) {
        if (c == '(') { ++depth; if (depth > max_depth) max_depth = depth; }
        else if (c == ')') { if (depth > 0) --depth; }
    }
    if (max_depth >= 8) ++indicators;

    return indicators >= 3;
}

int ContentAnalyzer::count_iframes(const std::string& html) {
    return count_occurrences_ci(html, "<iframe");
}

}  // namespace shieldtier
