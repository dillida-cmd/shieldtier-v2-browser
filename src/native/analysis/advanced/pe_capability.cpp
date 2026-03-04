#include "analysis/advanced/pe_capability.h"

#include <algorithm>

#include "common/json.h"

namespace shieldtier {

PeCapability::PeCapability() {
    capabilities_ = {
        {
            "Process Creation", "T1106",
            "Imports APIs for creating or executing new processes",
            Severity::kLow,
            {"CreateProcessA", "CreateProcessW", "CreateProcessAsUserA",
             "CreateProcessAsUserW", "WinExec", "ShellExecuteA", "ShellExecuteW",
             "ShellExecuteExA", "ShellExecuteExW"}
        },
        {
            "DLL Loading", "T1129",
            "Imports APIs for dynamic library loading and function resolution",
            Severity::kLow,
            {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
             "GetProcAddress", "LdrLoadDll"}
        },
        {
            "Memory Manipulation", "T1055",
            "Imports APIs for direct memory allocation and permission changes",
            Severity::kMedium,
            {"VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
             "HeapCreate", "HeapAlloc", "NtAllocateVirtualMemory",
             "NtProtectVirtualMemory", "WriteProcessMemory"}
        },
        {
            "Thread Management", "T1055",
            "Imports APIs for thread creation and context manipulation",
            Severity::kMedium,
            {"CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
             "SuspendThread", "ResumeThread", "SetThreadContext",
             "GetThreadContext", "NtCreateThreadEx", "RtlCreateUserThread",
             "QueueUserAPC"}
        },
        {
            "File Operations", "T1083",
            "Imports APIs for file system interaction",
            Severity::kInfo,
            {"CreateFileA", "CreateFileW", "WriteFile", "ReadFile",
             "DeleteFileA", "DeleteFileW", "CopyFileA", "CopyFileW",
             "MoveFileA", "MoveFileW", "GetTempPathA", "GetTempPathW"}
        },
        {
            "Registry Access", "T1112",
            "Imports APIs for Windows registry manipulation",
            Severity::kMedium,
            {"RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
             "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
             "RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteValueA", "RegDeleteValueW",
             "RegCreateKeyA", "RegCreateKeyW", "RegCreateKeyExA", "RegCreateKeyExW"}
        },
        {
            "Network Communication", "T1071",
            "Imports APIs for raw network socket operations",
            Severity::kMedium,
            {"socket", "connect", "send", "recv", "bind", "listen", "accept",
             "WSAStartup", "WSASocketA", "WSASocketW", "sendto", "recvfrom",
             "getaddrinfo", "gethostbyname"}
        },
        {
            "HTTP Communication", "T1071.001",
            "Imports APIs for HTTP/WinHTTP/WinINet operations",
            Severity::kMedium,
            {"InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
             "InternetConnectA", "InternetConnectW", "HttpOpenRequestA",
             "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
             "InternetReadFile", "WinHttpOpen", "WinHttpConnect",
             "WinHttpOpenRequest", "WinHttpSendRequest", "URLDownloadToFileA",
             "URLDownloadToFileW"}
        },
        {
            "Crypto Operations", "T1486",
            "Imports cryptographic APIs that may indicate ransomware behavior",
            Severity::kHigh,
            {"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptDeriveKey",
             "CryptAcquireContextA", "CryptAcquireContextW", "CryptImportKey",
             "CryptExportKey", "BCryptEncrypt", "BCryptDecrypt",
             "BCryptGenerateSymmetricKey", "BCryptOpenAlgorithmProvider"}
        },
        {
            "Service Management", "T1543.003",
            "Imports APIs for Windows service creation and control",
            Severity::kHigh,
            {"OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW",
             "StartServiceA", "StartServiceW", "ControlService",
             "ChangeServiceConfigA", "ChangeServiceConfigW", "DeleteService"}
        },
        {
            "Privilege Escalation", "T1134",
            "Imports APIs for token manipulation and privilege adjustment",
            Severity::kHigh,
            {"OpenProcessToken", "OpenThreadToken", "AdjustTokenPrivileges",
             "DuplicateTokenEx", "ImpersonateLoggedOnUser", "SetTokenInformation",
             "LookupPrivilegeValueA", "LookupPrivilegeValueW"}
        },
        {
            "Hooking", "T1056.001",
            "Imports APIs for installing input hooks or interceptors",
            Severity::kHigh,
            {"SetWindowsHookExA", "SetWindowsHookExW", "CallNextHookEx",
             "UnhookWindowsHookEx", "SetWinEventHook"}
        },
        {
            "Anti-Debug", "T1622",
            "Imports APIs commonly used to detect debugger presence",
            Severity::kMedium,
            {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
             "NtQueryInformationProcess", "OutputDebugStringA",
             "OutputDebugStringW", "NtSetInformationThread",
             "QueryPerformanceCounter", "GetTickCount"}
        },
        {
            "Clipboard Access", "T1115",
            "Imports APIs for clipboard data theft",
            Severity::kMedium,
            {"OpenClipboard", "GetClipboardData", "SetClipboardData",
             "EmptyClipboard", "CloseClipboard", "EnumClipboardFormats"}
        },
        {
            "Screen Capture", "T1113",
            "Imports APIs for capturing screen contents",
            Severity::kMedium,
            {"BitBlt", "StretchBlt", "GetDC", "GetWindowDC",
             "CreateCompatibleDC", "CreateCompatibleBitmap",
             "GetDIBits", "PrintWindow"}
        },
    };
}

std::vector<Finding> PeCapability::analyze(const std::vector<std::string>& imports) {
    std::vector<Finding> findings;

    for (const auto& cap : capabilities_) {
        std::vector<std::string> matched;
        for (const auto& api : cap.apis) {
            for (const auto& imp : imports) {
                if (imp == api) {
                    matched.push_back(api);
                    break;
                }
            }
        }

        if (!matched.empty()) {
            json meta;
            meta["capability"] = cap.name;
            meta["mitre_id"] = cap.mitre_id;
            meta["matched_apis"] = matched;
            meta["total_apis_in_category"] = cap.apis.size();

            findings.push_back({
                "PE Capability: " + cap.name,
                cap.description + " (" + std::to_string(matched.size()) +
                    " of " + std::to_string(cap.apis.size()) + " APIs found)",
                cap.severity,
                AnalysisEngine::kAdvanced,
                meta
            });
        }
    }

    return findings;
}

}  // namespace shieldtier
