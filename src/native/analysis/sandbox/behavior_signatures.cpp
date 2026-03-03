#include "analysis/sandbox/behavior_signatures.h"

namespace shieldtier {

BehaviorSignatures::BehaviorSignatures() {
    import_patterns_ = {
        {
            "process_injection_classic",
            {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
            "T1055.001",
            "Classic process injection via remote thread creation",
            Severity::kCritical,
        },
        {
            "apc_injection",
            {"VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC"},
            "T1055.004",
            "Asynchronous procedure call injection",
            Severity::kCritical,
        },
        {
            "process_hollowing",
            {"CreateProcess", "NtUnmapViewOfSection", "WriteProcessMemory", "ResumeThread"},
            "T1055.012",
            "Process hollowing — replaces legitimate process image in memory",
            Severity::kCritical,
        },
        {
            "lsass_credential_dump",
            {"OpenProcess", "ReadProcessMemory", "MiniDumpWriteDump"},
            "T1003.001",
            "LSASS memory credential harvesting",
            Severity::kCritical,
        },
        {
            "token_manipulation",
            {"OpenProcessToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser"},
            "T1134",
            "Access token theft and privilege escalation",
            Severity::kHigh,
        },
        {
            "service_persistence",
            {"OpenSCManager", "CreateService", "StartService"},
            "T1543.003",
            "Windows service creation for persistence",
            Severity::kHigh,
        },
        {
            "keylogging",
            {"SetWindowsHookEx", "GetAsyncKeyState"},
            "T1056.001",
            "Keyboard input capture via hooks or async key state polling",
            Severity::kHigh,
        },
        {
            "ransomware_behavior",
            {"FindFirstFile", "CryptEncrypt", "WriteFile", "DeleteFile"},
            "T1486",
            "File enumeration, encryption, and deletion — ransomware pattern",
            Severity::kCritical,
        },
        {
            "download_execute",
            {"InternetOpen", "InternetOpenUrl", "CreateProcess"},
            "T1105",
            "Downloads remote payload and executes it",
            Severity::kHigh,
        },
        {
            "anti_debug_timing",
            {"GetTickCount", "Sleep", "IsDebuggerPresent"},
            "T1497.003",
            "Timing-based anti-debugging and evasion checks",
            Severity::kMedium,
        },
        {
            "screen_capture",
            {"BitBlt", "GetDC", "CreateCompatibleBitmap"},
            "T1113",
            "Screen content capture via GDI",
            Severity::kMedium,
        },
        {
            "system_discovery",
            {"GetComputerName", "GetUserName", "GetSystemInfo"},
            "T1082",
            "System and environment enumeration",
            Severity::kLow,
        },
    };

    string_patterns_ = {
        {
            "powershell_encoded_command",
            "-EncodedCommand",
            "T1059.001",
            "PowerShell encoded command execution — often used to hide malicious scripts",
            Severity::kHigh,
        },
        {
            "powershell_enc_short",
            "-enc ",
            "T1059.001",
            "PowerShell encoded command (short flag)",
            Severity::kHigh,
        },
        {
            "registry_run_key",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "T1547.001",
            "Registry Run key persistence — auto-start on login",
            Severity::kHigh,
        },
        {
            "scheduled_task_creation",
            "schtasks /create",
            "T1053.005",
            "Scheduled task creation for persistence or execution",
            Severity::kHigh,
        },
        {
            "certutil_decode",
            "certutil -decode",
            "T1140",
            "Certutil used to decode obfuscated payloads",
            Severity::kHigh,
        },
        {
            "certutil_decode_slash",
            "certutil /decode",
            "T1140",
            "Certutil used to decode obfuscated payloads",
            Severity::kHigh,
        },
        {
            "bitsadmin_download",
            "bitsadmin /transfer",
            "T1197",
            "BITS transfer abuse for stealthy file download",
            Severity::kHigh,
        },
        {
            "cmd_execution",
            "cmd.exe /c",
            "T1059.003",
            "Command-line interpreter execution",
            Severity::kMedium,
        },
        {
            "wmi_execution",
            "wmic process",
            "T1047",
            "WMI process execution or enumeration",
            Severity::kMedium,
        },
        {
            "net_user_enum",
            "net user",
            "T1136",
            "Local account enumeration or creation",
            Severity::kMedium,
        },
        {
            "net_localgroup_enum",
            "net localgroup",
            "T1136",
            "Local group enumeration or modification",
            Severity::kMedium,
        },
        {
            "disable_defender_registry",
            "DisableAntiSpyware",
            "T1562.001",
            "Windows Defender disable via registry — defense evasion",
            Severity::kCritical,
        },
        {
            "disable_defender_powershell",
            "Set-MpPreference",
            "T1562.001",
            "Windows Defender configuration change via PowerShell",
            Severity::kCritical,
        },
        {
            "debug_detection_string",
            "IsDebuggerPresent",
            "T1622",
            "Anti-debug API reference in strings",
            Severity::kLow,
        },
    };
}

const std::vector<ImportPattern>& BehaviorSignatures::import_patterns() const {
    return import_patterns_;
}

const std::vector<StringPattern>& BehaviorSignatures::string_patterns() const {
    return string_patterns_;
}

}  // namespace shieldtier
