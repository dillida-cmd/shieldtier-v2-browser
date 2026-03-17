#include "analysis/yara/rule_manager.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace shieldtier {
namespace {

constexpr const char* kRuleUPXPacked = R"yara(
rule shieldtier_pe_upx_packed {
    meta:
        description = "Detects UPX packed executables"
        author = "ShieldTier"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $upx_sig = {55 50 58 21}
    condition:
        uint16(0) == 0x5A4D and ($upx0 and $upx1) or $upx_sig
}
)yara";

constexpr const char* kRuleSuspiciousImports = R"yara(
rule shieldtier_pe_suspicious_imports {
    meta:
        description = "Detects PE with process injection imports"
        author = "ShieldTier"
        severity = "high"
    strings:
        $va = "VirtualAlloc" ascii wide
        $wpm = "WriteProcessMemory" ascii wide
        $crt = "CreateRemoteThread" ascii wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
)yara";

constexpr const char* kRuleEicarTest = R"yara(
rule shieldtier_eicar_test {
    meta:
        description = "EICAR anti-malware test file"
        author = "ShieldTier"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0
}
)yara";

constexpr const char* kRulePowerShellEncoded = R"yara(
rule shieldtier_powershell_encoded {
    meta:
        description = "Detects base64-encoded PowerShell commands"
        author = "ShieldTier"
        severity = "high"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase
        $enc1 = "-enc " ascii nocase
        $enc2 = "-EncodedCommand " ascii nocase
        $enc3 = "-ec " ascii nocase
    condition:
        ($ps1 or $ps2) and ($enc1 or $enc2 or $enc3)
}
)yara";

constexpr const char* kRuleMacroAutoOpen = R"yara(
rule shieldtier_macro_autoopen {
    meta:
        description = "Detects Office documents with auto-execution macros"
        author = "ShieldTier"
        severity = "medium"
    strings:
        $a1 = "Auto_Open" ascii nocase
        $a2 = "AutoExec" ascii nocase
        $a3 = "Document_Open" ascii nocase
        $a4 = "AutoOpen" ascii nocase
        $a5 = "Workbook_Open" ascii nocase
    condition:
        any of them
}
)yara";

}  // namespace

RuleManager::RuleManager() {
    load_builtin_rules();
}

void RuleManager::load_builtin_rules() {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back({"shieldtier_pe_upx_packed", kRuleUPXPacked, "builtin"});
    rules_.push_back({"shieldtier_pe_suspicious_imports", kRuleSuspiciousImports, "builtin"});
    rules_.push_back({"shieldtier_eicar_test", kRuleEicarTest, "builtin"});
    rules_.push_back({"shieldtier_powershell_encoded", kRulePowerShellEncoded, "builtin"});
    rules_.push_back({"shieldtier_macro_autoopen", kRuleMacroAutoOpen, "builtin"});
}

Result<bool> RuleManager::add_rule(const std::string& name,
                                   const std::string& source,
                                   const std::string& origin) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back({name, source, origin});
    return true;
}

Result<bool> RuleManager::load_from_directory(const std::string& path) {
    namespace fs = std::filesystem;

    if (!fs::exists(path) || !fs::is_directory(path)) {
        return Error("Directory does not exist: " + path, "ENOENT");
    }

    for (const auto& entry : fs::directory_iterator(path)) {
        if (!entry.is_regular_file()) continue;

        auto ext = entry.path().extension().string();
        if (ext != ".yar" && ext != ".yara") continue;

        std::ifstream file(entry.path());
        if (!file.is_open()) continue;

        std::ostringstream ss;
        ss << file.rdbuf();

        auto name = entry.path().stem().string();
        auto result = add_rule(name, ss.str(), "file:" + entry.path().string());
        if (!result.ok()) return result;
    }

    return true;
}

std::vector<RuleSet> RuleManager::get_all_rules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_;
}

size_t RuleManager::rule_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
}

}  // namespace shieldtier
