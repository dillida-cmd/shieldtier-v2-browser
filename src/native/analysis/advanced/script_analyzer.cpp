#include "analysis/advanced/script_analyzer.h"

#include <algorithm>
#include <regex>
#include <string>

namespace shieldtier {

namespace {

bool contains_ci(const std::string& haystack, const std::string& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) { return std::tolower(a) == std::tolower(b); }
    );
    return it != haystack.end();
}

}  // namespace

std::vector<Finding> ScriptAnalyzer::analyze(const uint8_t* data, size_t size) {
    if (!data || size == 0) return {};
    constexpr size_t kMaxScanBytes = 16 * 1024 * 1024;
    std::string content(reinterpret_cast<const char*>(data), std::min(size, kMaxScanBytes));
    std::vector<Finding> findings;

    auto ps = detect_powershell(content);
    findings.insert(findings.end(), ps.begin(), ps.end());

    auto vba = detect_vba_macros(content);
    findings.insert(findings.end(), vba.begin(), vba.end());

    auto js = detect_javascript(content);
    findings.insert(findings.end(), js.begin(), js.end());

    auto bat = detect_batch(content);
    findings.insert(findings.end(), bat.begin(), bat.end());

    auto b64 = detect_base64_payload(content);
    findings.insert(findings.end(), b64.begin(), b64.end());

    return findings;
}

std::vector<Finding> ScriptAnalyzer::detect_powershell(const std::string& content) {
    std::vector<Finding> findings;

    struct Pattern {
        std::string marker;
        std::string desc;
    };

    std::vector<Pattern> patterns = {
        {"-EncodedCommand", "Encoded PowerShell command parameter"},
        {"-enc ", "Shortened encoded command parameter"},
        {"powershell -e ", "PowerShell invocation with encoded payload"},
        {"-WindowStyle Hidden", "Hidden window execution"},
        {"powershell.exe -nop", "PowerShell with no profile (evasion)"},
        {"Invoke-Expression", "Dynamic code execution via IEX"},
        {"IEX(", "Dynamic code execution via IEX shorthand"},
        {"[System.Convert]::FromBase64String", "Base64 decoding in PowerShell"},
        {"New-Object System.Net.WebClient", "Network download capability"},
        {"DownloadString(", "Remote payload download"},
        {"DownloadFile(", "Remote file download"},
        {"Invoke-WebRequest", "HTTP request capability"},
        {"-ExecutionPolicy Bypass", "Execution policy bypass"},
    };

    std::vector<std::string> matched;
    for (const auto& p : patterns) {
        if (contains_ci(content, p.marker)) {
            matched.push_back(p.marker);
        }
    }

    if (!matched.empty()) {
        json meta;
        meta["language"] = "powershell";
        meta["matched_patterns"] = matched;
        findings.push_back({
            "Script: Suspicious PowerShell Detected",
            "Found " + std::to_string(matched.size()) +
                " suspicious PowerShell pattern(s) indicating potential malicious execution",
            Severity::kHigh,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    return findings;
}

std::vector<Finding> ScriptAnalyzer::detect_vba_macros(const std::string& content) {
    std::vector<Finding> findings;

    std::vector<std::string> markers = {
        "AutoOpen", "Document_Open", "Workbook_Open", "Auto_Open",
        "Auto_Close", "Document_Close",
    };

    std::vector<std::string> dangerous = {
        "Shell(", "WScript.Shell", "Scripting.FileSystemObject",
        "CreateObject(", "CallByName", "MacroOptions",
        "Application.Run", "Environ(",
    };

    std::vector<std::string> matched_auto;
    for (const auto& m : markers) {
        if (content.find(m) != std::string::npos) {
            matched_auto.push_back(m);
        }
    }

    std::vector<std::string> matched_dangerous;
    for (const auto& d : dangerous) {
        if (content.find(d) != std::string::npos) {
            matched_dangerous.push_back(d);
        }
    }

    if (!matched_auto.empty() || !matched_dangerous.empty()) {
        json meta;
        meta["language"] = "vba";
        meta["auto_exec_triggers"] = matched_auto;
        meta["dangerous_functions"] = matched_dangerous;

        Severity sev = !matched_auto.empty() && !matched_dangerous.empty()
            ? Severity::kHigh : Severity::kMedium;

        findings.push_back({
            "Script: VBA Macro Indicators Detected",
            "Found " + std::to_string(matched_auto.size()) + " auto-exec trigger(s) and " +
                std::to_string(matched_dangerous.size()) + " dangerous function(s)",
            sev,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    return findings;
}

std::vector<Finding> ScriptAnalyzer::detect_javascript(const std::string& content) {
    std::vector<Finding> findings;

    std::vector<std::string> patterns = {
        "eval(", "Function(", "String.fromCharCode",
        "atob(", "decodeURIComponent", "unescape(",
        "document.write(", "setTimeout(", "setInterval(",
        "ActiveXObject", "WScript.Shell",
    };

    std::vector<std::string> matched;
    for (const auto& p : patterns) {
        if (content.find(p) != std::string::npos) {
            matched.push_back(p);
        }
    }

    if (!matched.empty()) {
        json meta;
        meta["language"] = "javascript";
        meta["matched_patterns"] = matched;
        findings.push_back({
            "Script: JavaScript Obfuscation Indicators",
            "Found " + std::to_string(matched.size()) +
                " JavaScript pattern(s) associated with code obfuscation or dynamic execution",
            Severity::kMedium,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    return findings;
}

std::vector<Finding> ScriptAnalyzer::detect_batch(const std::string& content) {
    std::vector<Finding> findings;

    struct Pattern {
        std::string marker;
        std::string desc;
    };

    std::vector<Pattern> patterns = {
        {"certutil -decode", "Certificate utility abuse for decoding"},
        {"certutil -urlcache", "Certificate utility abuse for downloading"},
        {"bitsadmin /transfer", "BITS transfer abuse for downloading"},
        {"powershell -", "PowerShell invocation from batch"},
        {"reg add", "Registry modification"},
        {"schtasks /create", "Scheduled task creation"},
        {"net user", "User account manipulation"},
        {"net localgroup", "Local group manipulation"},
        {"sc create", "Service creation"},
        {"wmic process", "WMI process manipulation"},
        {"vssadmin delete", "Shadow copy deletion (ransomware indicator)"},
        {"bcdedit /set", "Boot configuration manipulation"},
    };

    std::vector<std::string> matched;
    for (const auto& p : patterns) {
        if (contains_ci(content, p.marker)) {
            matched.push_back(p.marker);
        }
    }

    if (!matched.empty()) {
        json meta;
        meta["language"] = "batch";
        meta["matched_patterns"] = matched;
        findings.push_back({
            "Script: Suspicious Batch Commands Detected",
            "Found " + std::to_string(matched.size()) +
                " suspicious batch command pattern(s)",
            Severity::kMedium,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    return findings;
}

std::vector<Finding> ScriptAnalyzer::detect_base64_payload(const std::string& content) {
    std::vector<Finding> findings;

    // Match base64 strings of 100+ characters
    std::regex b64_re("[A-Za-z0-9+/]{100,}={0,2}");
    auto begin = std::sregex_iterator(content.begin(), content.end(), b64_re);
    auto end = std::sregex_iterator();

    int count = 0;
    size_t max_len = 0;
    for (auto it = begin; it != end; ++it) {
        ++count;
        max_len = std::max(max_len, it->length());
    }

    if (count > 0) {
        json meta;
        meta["base64_strings_found"] = count;
        meta["longest_length"] = max_len;
        findings.push_back({
            "Script: Embedded Base64 Payload Detected",
            "Found " + std::to_string(count) +
                " base64-encoded string(s), longest is " +
                std::to_string(max_len) + " characters",
            Severity::kMedium,
            AnalysisEngine::kAdvanced,
            meta
        });
    }

    return findings;
}

}  // namespace shieldtier
