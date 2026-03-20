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

// ─── Category 1: Ransomware (5 rules) ───

constexpr const char* kRuleCryptoLockerStrings = R"yara(
rule shieldtier_ransomware_cryptolocker {
    meta:
        description = "Detects CryptoLocker-style ransomware strings"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1486"
    strings:
        $s1 = "Your personal files are encrypted" ascii wide nocase
        $s2 = "CryptoLocker" ascii wide
        $s3 = "RSA-2048" ascii wide
        $s4 = "decrypt" ascii wide nocase
        $s5 = "bitcoin" ascii wide nocase
        $s6 = "wallet" ascii wide nocase
        $ransom = /pay\s+(the\s+)?ransom/i
    condition:
        3 of them
}
)yara";

constexpr const char* kRuleRansomNote = R"yara(
rule shieldtier_ransomware_ransom_note {
    meta:
        description = "Detects common ransom note patterns and payment instructions"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1486"
    strings:
        $n1 = "All your files have been encrypted" ascii wide nocase
        $n2 = "README_TO_DECRYPT" ascii nocase
        $n3 = "DECRYPT_INSTRUCTION" ascii nocase
        $n4 = "HOW_TO_RECOVER" ascii nocase
        $n5 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase
        $n6 = "pay within" ascii wide nocase
        $n7 = ".onion" ascii
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        2 of ($n*) or ($btc and 1 of ($n*))
}
)yara";

constexpr const char* kRuleShadowCopyDeletion = R"yara(
rule shieldtier_ransomware_shadow_delete {
    meta:
        description = "Detects Volume Shadow Copy deletion commonly used by ransomware"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1490"
    strings:
        $v1 = "vssadmin delete shadows" ascii wide nocase
        $v2 = "vssadmin.exe Delete Shadows /All" ascii wide nocase
        $v3 = "wmic shadowcopy delete" ascii wide nocase
        $v4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $v5 = "wbadmin delete catalog" ascii wide nocase
        $v6 = "delete shadows /all /quiet" ascii wide nocase
    condition:
        any of them
}
)yara";

constexpr const char* kRuleCryptoAPIFileEnum = R"yara(
rule shieldtier_ransomware_crypto_file_enum {
    meta:
        description = "Detects crypto API usage combined with file enumeration (ransomware pattern)"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1486"
    strings:
        $crypto1 = "CryptEncrypt" ascii wide
        $crypto2 = "CryptGenKey" ascii wide
        $crypto3 = "CryptImportKey" ascii wide
        $crypto4 = "BCryptEncrypt" ascii wide
        $enum1 = "FindFirstFile" ascii wide
        $enum2 = "FindNextFile" ascii wide
        $ext1 = ".docx" ascii wide
        $ext2 = ".xlsx" ascii wide
        $ext3 = ".pdf" ascii wide
        $ext4 = ".jpg" ascii wide
    condition:
        uint16(0) == 0x5A4D and 1 of ($crypto*) and all of ($enum*) and 2 of ($ext*)
}
)yara";

constexpr const char* kRuleRansomwareFileExtChange = R"yara(
rule shieldtier_ransomware_ext_change {
    meta:
        description = "Detects ransomware file extension modification patterns"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1486"
    strings:
        $move = "MoveFileEx" ascii wide
        $rename = "rename" ascii
        $enc_ext1 = ".encrypted" ascii wide
        $enc_ext2 = ".locked" ascii wide
        $enc_ext3 = ".crypt" ascii wide
        $enc_ext4 = ".enc" ascii wide
        $enum1 = "FindFirstFile" ascii wide
        $enum2 = "FindNextFile" ascii wide
    condition:
        uint16(0) == 0x5A4D and ($move or $rename) and 1 of ($enc_ext*) and 1 of ($enum*)
}
)yara";

// ─── Category 2: Trojans / RATs (5 rules) ───

constexpr const char* kRuleReverseShell = R"yara(
rule shieldtier_rat_reverse_shell {
    meta:
        description = "Detects reverse shell patterns via socket and command execution"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1059"
    strings:
        $ws1 = "WSAStartup" ascii wide
        $ws2 = "WSASocket" ascii wide
        $sock = "socket" ascii
        $conn = "connect" ascii
        $cmd1 = "cmd.exe" ascii wide
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "/bin/bash" ascii
        $cp = "CreateProcess" ascii wide
    condition:
        ($ws1 or $sock) and $conn and ($cmd1 or $cmd2 or $cmd3) and $cp
}
)yara";

constexpr const char* kRuleSocketExec = R"yara(
rule shieldtier_rat_socket_exec {
    meta:
        description = "Detects socket communication combined with command execution"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1071.001"
    strings:
        $s1 = "socket" ascii
        $s2 = "connect" ascii
        $s3 = "recv" ascii
        $s4 = "send" ascii
        $e1 = "exec" ascii
        $e2 = "system" ascii
        $e3 = "popen" ascii
        $e4 = "ShellExecute" ascii wide
    condition:
        3 of ($s*) and 1 of ($e*)
}
)yara";

constexpr const char* kRuleNetcatIndicators = R"yara(
rule shieldtier_rat_netcat {
    meta:
        description = "Detects Netcat and Ncat reverse shell indicators"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1059"
    strings:
        $nc1 = "nc.exe" ascii wide nocase
        $nc2 = "ncat.exe" ascii wide nocase
        $nc3 = "netcat" ascii wide nocase
        $flag1 = " -e " ascii
        $flag2 = " -c " ascii
        $flag3 = " -lvp " ascii
        $flag4 = " -nv " ascii
    condition:
        1 of ($nc*) and 1 of ($flag*)
}
)yara";

constexpr const char* kRuleMeterpreter = R"yara(
rule shieldtier_rat_meterpreter {
    meta:
        description = "Detects Meterpreter payload indicators"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1059.001"
    strings:
        $m1 = "metsrv" ascii wide
        $m2 = "stdapi" ascii wide
        $m3 = "priv_elevate" ascii
        $m4 = "core_channel_open" ascii
        $m5 = "ext_server_stdapi" ascii
        $rc4 = {FC E8 82 00 00 00 60 89 E5}
        $rev_tcp = {6A 05 68}
    condition:
        2 of ($m*) or $rc4 or ($rev_tcp and 1 of ($m*))
}
)yara";

constexpr const char* kRuleCobaltStrikeBeacon = R"yara(
rule shieldtier_rat_cobaltstrike_beacon {
    meta:
        description = "Detects CobaltStrike beacon indicators"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1071.001"
    strings:
        $cs1 = "%s.4444" ascii
        $cs2 = "beacon.dll" ascii wide
        $cs3 = "beacon.exe" ascii wide
        $cs4 = "ReflectiveLoader" ascii
        $cs5 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $pipe = {2E 00 70 00 69 00 70 00 65 00 5C 00}
        $cfg = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
    condition:
        2 of ($cs*) or $cfg or ($pipe and 1 of ($cs*))
}
)yara";

// ─── Category 3: Credential Stealers (5 rules) ───

constexpr const char* kRuleMimikatzStrings = R"yara(
rule shieldtier_credstealer_mimikatz {
    meta:
        description = "Detects Mimikatz credential harvesting tool strings"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1003.001"
    strings:
        $m1 = "mimikatz" ascii wide nocase
        $m2 = "gentilkiwi" ascii wide
        $m3 = "sekurlsa" ascii wide
        $m4 = "kerberos::list" ascii wide
        $m5 = "lsadump::sam" ascii wide
        $m6 = "privilege::debug" ascii wide
        $m7 = "token::elevate" ascii wide
        $m8 = "dpapi::masterkey" ascii wide
    condition:
        2 of them
}
)yara";

constexpr const char* kRuleLsassDump = R"yara(
rule shieldtier_credstealer_lsass_dump {
    meta:
        description = "Detects LSASS process memory dumping techniques"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1003.001"
    strings:
        $lsass = "lsass.exe" ascii wide nocase
        $api1 = "MiniDumpWriteDump" ascii wide
        $api2 = "OpenProcess" ascii wide
        $api3 = "dbghelp" ascii wide nocase
        $api4 = "comsvcs.dll" ascii wide nocase
        $cmd1 = "procdump" ascii wide nocase
        $cmd2 = "rundll32" ascii wide nocase
        $flag = "MiniDump" ascii wide
    condition:
        $lsass and (1 of ($api*) or ($cmd2 and $api4) or $cmd1)
}
)yara";

constexpr const char* kRuleSAMRegistryAccess = R"yara(
rule shieldtier_credstealer_sam_access {
    meta:
        description = "Detects SAM/SYSTEM registry hive access for credential extraction"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1003.002"
    strings:
        $sam1 = "HKLM\\SAM" ascii wide nocase
        $sam2 = "HKLM\\SYSTEM" ascii wide nocase
        $sam3 = "HKLM\\SECURITY" ascii wide nocase
        $reg1 = "reg save" ascii wide nocase
        $reg2 = "reg.exe save" ascii wide nocase
        $api1 = "RegSaveKey" ascii wide
        $api2 = "RegOpenKeyEx" ascii wide
    condition:
        1 of ($sam*) and (1 of ($reg*) or 1 of ($api*))
}
)yara";

constexpr const char* kRuleBrowserCredStealer = R"yara(
rule shieldtier_credstealer_browser {
    meta:
        description = "Detects browser credential and cookie theft patterns"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1555.003"
    strings:
        $chrome1 = "Login Data" ascii wide
        $chrome2 = "\\Google\\Chrome\\User Data" ascii wide
        $ff1 = "logins.json" ascii wide
        $ff2 = "\\Mozilla\\Firefox\\Profiles" ascii wide
        $edge1 = "\\Microsoft\\Edge\\User Data" ascii wide
        $cookie = "Cookies" ascii wide
        $db = "Web Data" ascii wide
        $decrypt1 = "CryptUnprotectData" ascii wide
        $decrypt2 = "BCryptDecrypt" ascii wide
    condition:
        2 of ($chrome*, $ff*, $edge*) and ($cookie or $db) and 1 of ($decrypt*)
}
)yara";

constexpr const char* kRuleCredentialPhishing = R"yara(
rule shieldtier_credstealer_keylogger {
    meta:
        description = "Detects keylogger and input capture API usage patterns"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1056.001"
    strings:
        $k1 = "GetAsyncKeyState" ascii wide
        $k2 = "SetWindowsHookEx" ascii wide
        $k3 = "GetKeyState" ascii wide
        $k4 = "GetKeyboardState" ascii wide
        $k5 = "MapVirtualKey" ascii wide
        $log1 = "keylog" ascii wide nocase
        $log2 = "keystroke" ascii wide nocase
        $clip = "GetClipboardData" ascii wide
    condition:
        uint16(0) == 0x5A4D and (2 of ($k*) or ($k2 and ($log1 or $log2)) or ($clip and 1 of ($k*)))
}
)yara";

// ─── Category 4: Dropper / Downloader (5 rules) ───

constexpr const char* kRulePowerShellDownload = R"yara(
rule shieldtier_dropper_ps_download {
    meta:
        description = "Detects PowerShell download cradle patterns"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $ps = "powershell" ascii wide nocase
        $d1 = "Invoke-WebRequest" ascii wide nocase
        $d2 = "Net.WebClient" ascii wide nocase
        $d3 = "DownloadFile" ascii wide nocase
        $d4 = "DownloadString" ascii wide nocase
        $d5 = "Invoke-Expression" ascii wide nocase
        $d6 = "IEX" ascii wide
        $d7 = "Start-BitsTransfer" ascii wide nocase
        $d8 = "wget" ascii wide nocase
        $d9 = "curl" ascii wide nocase
    condition:
        $ps and 2 of ($d*)
}
)yara";

constexpr const char* kRuleCertutilDownload = R"yara(
rule shieldtier_dropper_certutil {
    meta:
        description = "Detects certutil used for downloading or decoding payloads"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1140"
    strings:
        $cert = "certutil" ascii wide nocase
        $dl = "-urlcache" ascii wide nocase
        $dec = "-decode" ascii wide nocase
        $split = "-split" ascii wide nocase
        $f = "-f" ascii wide
    condition:
        $cert and ($dl or $dec) and ($split or $f)
}
)yara";

constexpr const char* kRuleBitsadminDownload = R"yara(
rule shieldtier_dropper_bitsadmin {
    meta:
        description = "Detects BITSAdmin used for downloading payloads"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1197"
    strings:
        $bits = "bitsadmin" ascii wide nocase
        $t1 = "/transfer" ascii wide nocase
        $t2 = "/create" ascii wide nocase
        $t3 = "/addfile" ascii wide nocase
        $t4 = "/resume" ascii wide nocase
        $t5 = "/complete" ascii wide nocase
        $http = "http" ascii wide nocase
    condition:
        $bits and ($t1 or ($t2 and $t3)) and $http
}
)yara";

constexpr const char* kRuleMshtaExec = R"yara(
rule shieldtier_dropper_mshta {
    meta:
        description = "Detects MSHTA abuse for downloading and executing payloads"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1218.005"
    strings:
        $mshta = "mshta" ascii wide nocase
        $vb1 = "vbscript" ascii wide nocase
        $vb2 = "javascript" ascii wide nocase
        $http = "http" ascii wide nocase
        $exec1 = "Execute" ascii wide
        $exec2 = "CreateObject" ascii wide
        $exec3 = "GetObject" ascii wide
    condition:
        $mshta and ($vb1 or $vb2) and ($http or 1 of ($exec*))
}
)yara";

constexpr const char* kRuleRegsvr32Exec = R"yara(
rule shieldtier_dropper_regsvr32 {
    meta:
        description = "Detects Regsvr32 (Squiblydoo) abuse for downloading payloads"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1218.010"
    strings:
        $regsvr = "regsvr32" ascii wide nocase
        $scrobj = "scrobj.dll" ascii wide nocase
        $s1 = "/s" ascii wide nocase
        $s2 = "/u" ascii wide nocase
        $s3 = "/i:" ascii wide nocase
        $http = "http" ascii wide nocase
    condition:
        $regsvr and ($scrobj or ($s3 and $http))
}
)yara";

// ─── Category 5: Persistence (5 rules) ───

constexpr const char* kRuleRegistryRunKeys = R"yara(
rule shieldtier_persistence_reg_run {
    meta:
        description = "Detects registry Run/RunOnce key persistence"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1547.001"
    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $run3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide nocase
        $run4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii wide nocase
        $api1 = "RegSetValueEx" ascii wide
        $api2 = "RegCreateKeyEx" ascii wide
    condition:
        1 of ($run*) and 1 of ($api*)
}
)yara";

constexpr const char* kRuleScheduledTask = R"yara(
rule shieldtier_persistence_schtask {
    meta:
        description = "Detects scheduled task creation for persistence"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1053.005"
    strings:
        $s1 = "schtasks" ascii wide nocase
        $s2 = "/create" ascii wide nocase
        $s3 = "/sc" ascii wide nocase
        $s4 = "/tn" ascii wide nocase
        $s5 = "/tr" ascii wide nocase
        $api1 = "ITaskService" ascii wide
        $api2 = "ITaskFolder" ascii wide
        $api3 = "RegisterTaskDefinition" ascii wide
    condition:
        ($s1 and $s2 and 2 of ($s3, $s4, $s5)) or 2 of ($api*)
}
)yara";

constexpr const char* kRuleWMIEventSubscription = R"yara(
rule shieldtier_persistence_wmi_event {
    meta:
        description = "Detects WMI event subscription for persistence"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1546.003"
    strings:
        $w1 = "__EventFilter" ascii wide
        $w2 = "CommandLineEventConsumer" ascii wide
        $w3 = "ActiveScriptEventConsumer" ascii wide
        $w4 = "__FilterToConsumerBinding" ascii wide
        $w5 = "__EventConsumer" ascii wide
        $w6 = "ExecMethod" ascii wide
        $w7 = "Win32_Process" ascii wide
    condition:
        2 of ($w1, $w2, $w3, $w4, $w5) or ($w6 and $w7)
}
)yara";

constexpr const char* kRuleStartupFolder = R"yara(
rule shieldtier_persistence_startup_folder {
    meta:
        description = "Detects writing files to Startup folder for persistence"
        author = "ShieldTier"
        severity = "medium"
        mitre = "T1547.001"
    strings:
        $s1 = "\\Start Menu\\Programs\\Startup" ascii wide
        $s2 = "\\Startup\\" ascii wide
        $s3 = "shell:startup" ascii wide nocase
        $s4 = "shell:common startup" ascii wide nocase
        $api1 = "CopyFile" ascii wide
        $api2 = "CreateFile" ascii wide
        $api3 = "MoveFile" ascii wide
        $api4 = "WriteFile" ascii wide
    condition:
        1 of ($s*) and 1 of ($api*)
}
)yara";

constexpr const char* kRuleServiceCreation = R"yara(
rule shieldtier_persistence_service {
    meta:
        description = "Detects Windows service creation for persistence"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1543.003"
    strings:
        $sc1 = "sc create" ascii wide nocase
        $sc2 = "sc.exe create" ascii wide nocase
        $api1 = "CreateService" ascii wide
        $api2 = "OpenSCManager" ascii wide
        $api3 = "ChangeServiceConfig" ascii wide
        $api4 = "StartService" ascii wide
        $reg = "SYSTEM\\CurrentControlSet\\Services" ascii wide
    condition:
        ($sc1 or $sc2) or ($api1 and $api2) or ($reg and ($api3 or $api4))
}
)yara";

// ─── Category 6: Rootkit / Evasion (5 rules) ───

constexpr const char* kRuleNtdllUnhooking = R"yara(
rule shieldtier_evasion_ntdll_unhook {
    meta:
        description = "Detects NTDLL unhooking to bypass EDR hooks"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1562.001"
    strings:
        $ntdll = "ntdll.dll" ascii wide nocase
        $api1 = "NtProtectVirtualMemory" ascii wide
        $api2 = "NtWriteVirtualMemory" ascii wide
        $api3 = "GetModuleHandle" ascii wide
        $api4 = "GetProcAddress" ascii wide
        $map1 = "NtMapViewOfSection" ascii wide
        $map2 = "MapViewOfFile" ascii wide
        $sec = ".text" ascii
    condition:
        $ntdll and $sec and (2 of ($api*) or 1 of ($map*))
}
)yara";

constexpr const char* kRuleSyscallStub = R"yara(
rule shieldtier_evasion_direct_syscall {
    meta:
        description = "Detects direct syscall stub patterns for EDR evasion"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1106"
    strings:
        $stub1 = { 4C 8B D1 B8 ?? 00 00 00 0F 05 C3 }
        $stub2 = { B8 ?? 00 00 00 BA 01 00 00 00 0F 05 }
        $stub3 = { 49 89 CA B8 ?? 00 00 00 0F 05 C3 }
        $syswhisper = "SysWhispers" ascii nocase
        $syscall_str = "NtAllocateVirtualMemory" ascii wide
        $syscall_str2 = "NtCreateThreadEx" ascii wide
    condition:
        1 of ($stub*) or ($syswhisper and 1 of ($syscall_str*))
}
)yara";

constexpr const char* kRuleHeavensGate = R"yara(
rule shieldtier_evasion_heavens_gate {
    meta:
        description = "Detects Heaven's Gate (WoW64 layer abuse) technique"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1106"
    strings:
        $gate1 = { EA ?? ?? ?? ?? 33 00 }
        $gate2 = { 6A 33 E8 ?? ?? ?? ?? 83 C4 04 }
        $gate3 = { E8 00 00 00 00 C7 44 24 04 23 00 00 00 }
        $wow64 = "Wow64Transition" ascii wide
        $cs_switch = { 9A ?? ?? ?? ?? 33 00 }
    condition:
        1 of ($gate*) or ($wow64 and $cs_switch)
}
)yara";

constexpr const char* kRuleProcessHollowing = R"yara(
rule shieldtier_evasion_process_hollowing {
    meta:
        description = "Detects process hollowing (RunPE) technique"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1055.012"
    strings:
        $api1 = "NtUnmapViewOfSection" ascii wide
        $api2 = "ZwUnmapViewOfSection" ascii wide
        $api3 = "CreateProcessA" ascii wide
        $api4 = "CreateProcessW" ascii wide
        $api5 = "WriteProcessMemory" ascii wide
        $api6 = "SetThreadContext" ascii wide
        $api7 = "ResumeThread" ascii wide
        $api8 = "NtSetContextThread" ascii wide
        $create_susp = { 04 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and ($api1 or $api2) and ($api3 or $api4) and $api5 and ($api6 or $api8) and $api7
}
)yara";

constexpr const char* kRuleReflectiveDLL = R"yara(
rule shieldtier_evasion_reflective_dll {
    meta:
        description = "Detects reflective DLL injection patterns"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1620"
    strings:
        $ref1 = "ReflectiveLoader" ascii wide
        $ref2 = "_ReflectiveLoader@4" ascii
        $ref3 = "reflective" ascii nocase
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "GetProcAddress" ascii wide
        $api3 = "LoadLibrary" ascii wide
        $mz = { 4D 5A }
        $pe_self = "IMAGE_DOS_HEADER" ascii
    condition:
        (1 of ($ref*) and 2 of ($api*)) or ($mz at 0 and $ref1)
}
)yara";

// ─── Category 7: Cryptominer (3 rules) ───

constexpr const char* kRuleXMRig = R"yara(
rule shieldtier_miner_xmrig {
    meta:
        description = "Detects XMRig cryptocurrency miner"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1496"
    strings:
        $x1 = "xmrig" ascii wide nocase
        $x2 = "XMRig" ascii
        $x3 = "randomx" ascii wide nocase
        $x4 = "cryptonight" ascii wide nocase
        $x5 = "--donate-level" ascii
        $x6 = "--coin monero" ascii nocase
        $pool1 = "pool.minergate" ascii nocase
        $pool2 = "xmrpool" ascii nocase
        $pool3 = "moneropool" ascii nocase
    condition:
        2 of ($x*) or 1 of ($pool*)
}
)yara";

constexpr const char* kRuleCoinhive = R"yara(
rule shieldtier_miner_coinhive {
    meta:
        description = "Detects Coinhive and browser-based cryptocurrency miners"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1496"
    strings:
        $c1 = "coinhive" ascii wide nocase
        $c2 = "CoinHive.Anonymous" ascii
        $c3 = "authedmine" ascii nocase
        $c4 = "coin-hive.com" ascii
        $c5 = "crypto-loot" ascii nocase
        $c6 = "JSEcoin" ascii nocase
        $wasm = "cryptonight.wasm" ascii
    condition:
        any of them
}
)yara";

constexpr const char* kRuleStratumProtocol = R"yara(
rule shieldtier_miner_stratum {
    meta:
        description = "Detects stratum mining protocol communication"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "stratum+tcp://" ascii wide
        $s2 = "stratum+ssl://" ascii wide
        $s3 = "stratum+udp://" ascii wide
        $m1 = "mining.subscribe" ascii
        $m2 = "mining.authorize" ascii
        $m3 = "mining.submit" ascii
        $m4 = "mining.notify" ascii
    condition:
        1 of ($s*) or 2 of ($m*)
}
)yara";

// ─── Category 8: Webshell (3 rules) ───

constexpr const char* kRuleWebshellPHP = R"yara(
rule shieldtier_webshell_php {
    meta:
        description = "Detects PHP webshell patterns with eval and encoded payloads"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $php = "<?php" ascii nocase
        $eval1 = "eval(" ascii nocase
        $eval2 = "assert(" ascii nocase
        $eval3 = "preg_replace" ascii nocase
        $b64 = "base64_decode" ascii nocase
        $exec1 = "system(" ascii nocase
        $exec2 = "passthru(" ascii nocase
        $exec3 = "shell_exec(" ascii nocase
        $exec4 = "exec(" ascii nocase
        $exec5 = "popen(" ascii nocase
        $rot = "str_rot13" ascii nocase
        $gz = "gzinflate" ascii nocase
    condition:
        $php and (($eval1 and $b64) or ($eval1 and ($rot or $gz)) or 2 of ($exec*))
}
)yara";

constexpr const char* kRuleWebshellASP = R"yara(
rule shieldtier_webshell_asp {
    meta:
        description = "Detects ASP/ASPX webshell with command execution"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $asp1 = "<%@ " ascii nocase
        $asp2 = "<script runat=" ascii nocase
        $asp3 = "<%eval" ascii nocase
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "Process.Start" ascii
        $cmd3 = "CreateObject" ascii
        $cmd4 = "WScript.Shell" ascii
        $cmd5 = "Scripting.FileSystemObject" ascii
        $exec = "Execute(" ascii nocase
        $req = "Request(" ascii nocase
    condition:
        1 of ($asp*) and (1 of ($cmd*) or ($exec and $req))
}
)yara";

constexpr const char* kRuleWebshellJSP = R"yara(
rule shieldtier_webshell_jsp {
    meta:
        description = "Detects JSP webshell with runtime command execution"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $jsp1 = "<%@page" ascii nocase
        $jsp2 = "<%@ page" ascii nocase
        $jsp3 = "<jsp:" ascii nocase
        $rt1 = "Runtime.getRuntime()" ascii
        $rt2 = "ProcessBuilder" ascii
        $rt3 = "getRuntime().exec" ascii
        $req = "request.getParameter" ascii
        $io = "InputStream" ascii
    condition:
        1 of ($jsp*) and 1 of ($rt*) and ($req or $io)
}
)yara";

// ─── Category 9: Exploit Kit (3 rules) ───

constexpr const char* kRuleShellcodeNopSled = R"yara(
rule shieldtier_exploit_nop_sled {
    meta:
        description = "Detects NOP sled patterns commonly found in shellcode"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1203"
    strings:
        $nop16 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $nop_var1 = { 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 }
        $nop_var2 = { 0F 1F 00 0F 1F 00 0F 1F 00 0F 1F 00 }
        $shellcode_start = { 31 C0 50 68 }
        $shellcode_start2 = { 33 C0 50 68 }
        $shellcode_start3 = { FC E8 }
    condition:
        ($nop16 or $nop_var1 or $nop_var2) and 1 of ($shellcode_start*)
}
)yara";

constexpr const char* kRuleROPGadgetChain = R"yara(
rule shieldtier_exploit_rop_chain {
    meta:
        description = "Detects ROP gadget chain patterns in exploit payloads"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1203"
    strings:
        $rop_ntdll = { 00 00 ?? 77 00 00 ?? 77 00 00 ?? 77 00 00 ?? 77 }
        $rop_kernel32 = { 00 00 ?? 76 00 00 ?? 76 00 00 ?? 76 00 00 ?? 76 }
        $vp_str = "VirtualProtect" ascii wide
        $va_str = "VirtualAlloc" ascii wide
        $wp = "WriteProcessMemory" ascii wide
        $stack_pivot = { 94 C3 }
        $xchg_ret = { 87 ?? C3 }
    condition:
        ($rop_ntdll or $rop_kernel32) or (($vp_str or $va_str or $wp) and ($stack_pivot or $xchg_ret))
}
)yara";

constexpr const char* kRuleHeapSpray = R"yara(
rule shieldtier_exploit_heap_spray {
    meta:
        description = "Detects heap spray patterns in script-based exploits"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1203"
    strings:
        $hs1 = "unescape(" ascii nocase
        $hs2 = "spray" ascii nocase
        $hs3 = "0x0c0c0c0c" ascii nocase
        $hs4 = "%u0c0c%u0c0c" ascii nocase
        $hs5 = "\\x0c\\x0c\\x0c\\x0c" ascii
        $hs6 = "block_size" ascii
        $sub = "substr(" ascii nocase
        $while = "while" ascii
        $alloc = "new Array" ascii
        $chunk = "chunk" ascii nocase
    condition:
        (1 of ($hs3, $hs4, $hs5) and ($sub or $while)) or ($hs1 and $hs2 and ($alloc or $chunk))
}
)yara";

// ─── Category 10: Document Malware (5 rules) ───

constexpr const char* kRuleVBAAutoMacro = R"yara(
rule shieldtier_docmal_vba_auto {
    meta:
        description = "Detects VBA macros with auto-execution and suspicious functions"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1059.005"
    strings:
        $auto1 = "Auto_Open" ascii nocase
        $auto2 = "AutoOpen" ascii nocase
        $auto3 = "Document_Open" ascii nocase
        $auto4 = "Workbook_Open" ascii nocase
        $auto5 = "AutoExec" ascii nocase
        $sus1 = "Shell(" ascii nocase
        $sus2 = "WScript.Shell" ascii nocase
        $sus3 = "Environ(" ascii nocase
        $sus4 = "PowerShell" ascii nocase
        $sus5 = "CreateObject" ascii nocase
        $sus6 = "CallByName" ascii nocase
    condition:
        1 of ($auto*) and 2 of ($sus*)
}
)yara";

constexpr const char* kRuleDDEInjection = R"yara(
rule shieldtier_docmal_dde {
    meta:
        description = "Detects DDE injection in Office documents"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1559.002"
    strings:
        $dde1 = "DDE" ascii wide
        $dde2 = "DDEAUTO" ascii wide
        $dde3 = { 13 64 64 65 61 75 74 6F }
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "powershell" ascii wide nocase
        $cmd3 = "\\\\..\\..\\..\\windows\\system32" ascii wide nocase
        $quote = "QUOTE" ascii wide
    condition:
        ($dde1 or $dde2 or $dde3) and (1 of ($cmd*) or $quote)
}
)yara";

constexpr const char* kRuleOLEEmbedded = R"yara(
rule shieldtier_docmal_ole_embedded {
    meta:
        description = "Detects OLE embedded objects with executable content"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1566.001"
    strings:
        $ole1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $ole2 = "Root Entry" ascii wide
        $pkg1 = "Package" ascii wide
        $pkg2 = "OLE10Native" ascii wide
        $exe1 = { 4D 5A 90 00 }
        $exe2 = "This program" ascii
        $obj = "\\objemb" ascii
        $objdata = "\\objdata" ascii
    condition:
        $ole1 and ($pkg1 or $pkg2 or $obj or $objdata) and ($exe1 or $exe2)
}
)yara";

constexpr const char* kRuleRTFExploit = R"yara(
rule shieldtier_docmal_rtf_exploit {
    meta:
        description = "Detects RTF exploits with embedded objects (CVE-2017-11882 and similar)"
        author = "ShieldTier"
        severity = "critical"
        mitre = "T1203"
    strings:
        $rtf = "{\\rtf" ascii
        $obj1 = "\\objdata" ascii
        $obj2 = "\\objemb" ascii
        $obj3 = "\\objclass" ascii
        $clsid1 = "0002CE02" ascii nocase
        $clsid2 = "00021401" ascii nocase
        $eq = "Equation.3" ascii
        $shellcode = { 90 90 90 90 EB }
    condition:
        $rtf and 1 of ($obj*) and ($eq or 1 of ($clsid*) or $shellcode)
}
)yara";

constexpr const char* kRulePDFJavaScript = R"yara(
rule shieldtier_docmal_pdf_javascript {
    meta:
        description = "Detects PDF files with embedded JavaScript (potential exploit)"
        author = "ShieldTier"
        severity = "medium"
        mitre = "T1203"
    strings:
        $pdf = "%PDF" ascii
        $js1 = "/JavaScript" ascii
        $js2 = "/JS " ascii
        $js3 = "/JS(" ascii
        $aa = "/OpenAction" ascii
        $launch = "/Launch" ascii
        $uri = "/URI" ascii
        $eval = "eval" ascii
        $unescape = "unescape" ascii
        $spray = "spray" ascii nocase
    condition:
        $pdf and 1 of ($js*) and ($aa or $launch) and 1 of ($eval, $unescape, $spray)
}
)yara";

// ─── Category 11: Network Indicators (3 rules) ───

constexpr const char* kRuleBase64EncodedIP = R"yara(
rule shieldtier_network_b64_ip {
    meta:
        description = "Detects base64-encoded IP addresses and URLs used for C2"
        author = "ShieldTier"
        severity = "medium"
        mitre = "T1132.001"
    strings:
        $b64_http1 = "aHR0cDovL" ascii
        $b64_http2 = "aHR0cHM6Ly" ascii
        $b64_ftp = "ZnRwOi8v" ascii
        $decode1 = "base64" ascii nocase
        $decode2 = "atob" ascii nocase
        $decode3 = "FromBase64" ascii nocase
        $decode4 = "b64decode" ascii nocase
    condition:
        1 of ($b64*) and 1 of ($decode*)
}
)yara";

constexpr const char* kRuleHardcodedC2 = R"yara(
rule shieldtier_network_hardcoded_c2 {
    meta:
        description = "Detects hardcoded suspicious domain patterns used for C2 communication"
        author = "ShieldTier"
        severity = "high"
        mitre = "T1071.001"
    strings:
        $dga1 = /[a-z]{12,20}\.(xyz|top|tk|ml|ga|cf|gq|pw|cc)/ ascii
        $dga2 = /[a-z0-9]{16,}\.(com|net|org)/ ascii
        $noip = "no-ip.org" ascii nocase
        $dyn1 = "duckdns.org" ascii nocase
        $dyn2 = "ddns.net" ascii nocase
        $dyn3 = "hopto.org" ascii nocase
        $dyn4 = "zapto.org" ascii nocase
        $ngrok = "ngrok.io" ascii nocase
        $paste = "pastebin.com/raw/" ascii nocase
    condition:
        2 of them
}
)yara";

constexpr const char* kRuleDNSOverHTTPS = R"yara(
rule shieldtier_network_doh {
    meta:
        description = "Detects DNS over HTTPS usage for covert channel communication"
        author = "ShieldTier"
        severity = "medium"
        mitre = "T1071.004"
    strings:
        $doh1 = "dns-query" ascii
        $doh2 = "application/dns-message" ascii
        $doh3 = "cloudflare-dns.com" ascii
        $doh4 = "dns.google" ascii
        $doh5 = "1.1.1.1/dns-query" ascii
        $doh6 = "8.8.8.8/resolve" ascii
        $doh7 = "dns.quad9.net" ascii
        $doh8 = "doh.opendns.com" ascii
    condition:
        2 of them
}
)yara";

// ─── Category 12: Obfuscation (3 rules) ───

constexpr const char* kRuleStringStacking = R"yara(
rule shieldtier_obfuscation_string_stacking {
    meta:
        description = "Detects string stacking obfuscation technique (character-by-character string building)"
        author = "ShieldTier"
        severity = "medium"
        mitre = "T1027"
    strings:
        $stack1 = /mov\s+byte\s+ptr\s+\[ebp[-+]/ ascii
        $stack2 = /mov\s+byte\s+ptr\s+\[esp\+/ ascii
        $chr_concat = /Chr\(\d+\)\s*[&+]\s*Chr\(\d+\)\s*[&+]\s*Chr\(\d+\)/ ascii nocase
        $char_array = /char\[\]\s*=\s*\{.*,.*,.*,.*,.*\}/ ascii
        $js_fromcc = "String.fromCharCode(" ascii
        $ps_char = "[char]" ascii nocase
    condition:
        1 of ($stack*) or $chr_concat or ($char_array and filesize < 1MB) or ($js_fromcc and filesize < 500KB) or $ps_char
}
)yara";

constexpr const char* kRuleXORLoopDecode = R"yara(
rule shieldtier_obfuscation_xor_loop {
    meta:
        description = "Detects XOR loop decoding patterns used for payload decryption"
        author = "ShieldTier"
        severity = "medium"
        mitre = "T1140"
    strings:
        $xor_loop1 = { 30 ?? 4? E? F? }
        $xor_loop2 = { 80 3? ?? 74 ?? 80 3? ?? 30 }
        $xor_loop3 = { 31 ?? 83 C? 04 3B ?? 72 }
        $xor_str1 = "xor" ascii nocase
        $loop_str = /for\s*\(\s*(int|var|let)\s+\w+\s*=\s*0\s*;\s*\w+\s*<.*;\s*\w+\+\+\s*\).*\^/ ascii
        $py_xor = /\^\s*key\[/ ascii
    condition:
        1 of ($xor_loop*) or $loop_str or $py_xor
}
)yara";

constexpr const char* kRuleStackStringBuild = R"yara(
rule shieldtier_obfuscation_stack_strings {
    meta:
        description = "Detects stack-based string construction to evade static analysis"
        author = "ShieldTier"
        severity = "medium"
        mitre = "T1027"
    strings:
        $push_pattern = { 68 ?? ?? 00 00 68 ?? ?? 00 00 68 ?? ?? 00 00 68 ?? ?? 00 00 }
        $mov_dword1 = { C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? }
        $mov_dword2 = { C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? }
        $concat1 = "StringBuilder" ascii wide
        $concat2 = "String.Concat" ascii wide
        $join = "String.Join" ascii wide
    condition:
        1 of ($push_pattern, $mov_dword1, $mov_dword2) or (($concat1 or $concat2 or $join) and filesize < 500KB)
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

    // Ransomware
    rules_.push_back({"shieldtier_ransomware_cryptolocker", kRuleCryptoLockerStrings, "builtin"});
    rules_.push_back({"shieldtier_ransomware_ransom_note", kRuleRansomNote, "builtin"});
    rules_.push_back({"shieldtier_ransomware_shadow_delete", kRuleShadowCopyDeletion, "builtin"});
    rules_.push_back({"shieldtier_ransomware_crypto_file_enum", kRuleCryptoAPIFileEnum, "builtin"});
    rules_.push_back({"shieldtier_ransomware_ext_change", kRuleRansomwareFileExtChange, "builtin"});

    // Trojans / RATs
    rules_.push_back({"shieldtier_rat_reverse_shell", kRuleReverseShell, "builtin"});
    rules_.push_back({"shieldtier_rat_socket_exec", kRuleSocketExec, "builtin"});
    rules_.push_back({"shieldtier_rat_netcat", kRuleNetcatIndicators, "builtin"});
    rules_.push_back({"shieldtier_rat_meterpreter", kRuleMeterpreter, "builtin"});
    rules_.push_back({"shieldtier_rat_cobaltstrike_beacon", kRuleCobaltStrikeBeacon, "builtin"});

    // Credential Stealers
    rules_.push_back({"shieldtier_credstealer_mimikatz", kRuleMimikatzStrings, "builtin"});
    rules_.push_back({"shieldtier_credstealer_lsass_dump", kRuleLsassDump, "builtin"});
    rules_.push_back({"shieldtier_credstealer_sam_access", kRuleSAMRegistryAccess, "builtin"});
    rules_.push_back({"shieldtier_credstealer_browser", kRuleBrowserCredStealer, "builtin"});
    rules_.push_back({"shieldtier_credstealer_keylogger", kRuleCredentialPhishing, "builtin"});

    // Dropper / Downloader
    rules_.push_back({"shieldtier_dropper_ps_download", kRulePowerShellDownload, "builtin"});
    rules_.push_back({"shieldtier_dropper_certutil", kRuleCertutilDownload, "builtin"});
    rules_.push_back({"shieldtier_dropper_bitsadmin", kRuleBitsadminDownload, "builtin"});
    rules_.push_back({"shieldtier_dropper_mshta", kRuleMshtaExec, "builtin"});
    rules_.push_back({"shieldtier_dropper_regsvr32", kRuleRegsvr32Exec, "builtin"});

    // Persistence
    rules_.push_back({"shieldtier_persistence_reg_run", kRuleRegistryRunKeys, "builtin"});
    rules_.push_back({"shieldtier_persistence_schtask", kRuleScheduledTask, "builtin"});
    rules_.push_back({"shieldtier_persistence_wmi_event", kRuleWMIEventSubscription, "builtin"});
    rules_.push_back({"shieldtier_persistence_startup_folder", kRuleStartupFolder, "builtin"});
    rules_.push_back({"shieldtier_persistence_service", kRuleServiceCreation, "builtin"});

    // Rootkit / Evasion
    rules_.push_back({"shieldtier_evasion_ntdll_unhook", kRuleNtdllUnhooking, "builtin"});
    rules_.push_back({"shieldtier_evasion_direct_syscall", kRuleSyscallStub, "builtin"});
    rules_.push_back({"shieldtier_evasion_heavens_gate", kRuleHeavensGate, "builtin"});
    rules_.push_back({"shieldtier_evasion_process_hollowing", kRuleProcessHollowing, "builtin"});
    rules_.push_back({"shieldtier_evasion_reflective_dll", kRuleReflectiveDLL, "builtin"});

    // Cryptominer
    rules_.push_back({"shieldtier_miner_xmrig", kRuleXMRig, "builtin"});
    rules_.push_back({"shieldtier_miner_coinhive", kRuleCoinhive, "builtin"});
    rules_.push_back({"shieldtier_miner_stratum", kRuleStratumProtocol, "builtin"});

    // Webshell
    rules_.push_back({"shieldtier_webshell_php", kRuleWebshellPHP, "builtin"});
    rules_.push_back({"shieldtier_webshell_asp", kRuleWebshellASP, "builtin"});
    rules_.push_back({"shieldtier_webshell_jsp", kRuleWebshellJSP, "builtin"});

    // Exploit Kit
    rules_.push_back({"shieldtier_exploit_nop_sled", kRuleShellcodeNopSled, "builtin"});
    rules_.push_back({"shieldtier_exploit_rop_chain", kRuleROPGadgetChain, "builtin"});
    rules_.push_back({"shieldtier_exploit_heap_spray", kRuleHeapSpray, "builtin"});

    // Document Malware
    rules_.push_back({"shieldtier_docmal_vba_auto", kRuleVBAAutoMacro, "builtin"});
    rules_.push_back({"shieldtier_docmal_dde", kRuleDDEInjection, "builtin"});
    rules_.push_back({"shieldtier_docmal_ole_embedded", kRuleOLEEmbedded, "builtin"});
    rules_.push_back({"shieldtier_docmal_rtf_exploit", kRuleRTFExploit, "builtin"});
    rules_.push_back({"shieldtier_docmal_pdf_javascript", kRulePDFJavaScript, "builtin"});

    // Network Indicators
    rules_.push_back({"shieldtier_network_b64_ip", kRuleBase64EncodedIP, "builtin"});
    rules_.push_back({"shieldtier_network_hardcoded_c2", kRuleHardcodedC2, "builtin"});
    rules_.push_back({"shieldtier_network_doh", kRuleDNSOverHTTPS, "builtin"});

    // Obfuscation
    rules_.push_back({"shieldtier_obfuscation_string_stacking", kRuleStringStacking, "builtin"});
    rules_.push_back({"shieldtier_obfuscation_xor_loop", kRuleXORLoopDecode, "builtin"});
    rules_.push_back({"shieldtier_obfuscation_stack_strings", kRuleStackStringBuild, "builtin"});
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
