#include "vm/windows_sandbox.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
// Stubs for non-Windows builds — every public method returns an error.
#endif

namespace shieldtier {

namespace {

std::string generate_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 255);

    static constexpr char hex[] = "0123456789abcdef";
    std::string id;
    id.reserve(16);
    for (int i = 0; i < 8; ++i) {
        auto byte = static_cast<uint8_t>(dist(gen));
        id.push_back(hex[byte >> 4]);
        id.push_back(hex[byte & 0x0f]);
    }
    return "wsb_" + id;
}

// Embedded PowerShell agent script content.
// This is the same script that lives in sandbox_agent/agent.ps1 but we
// embed it so the C++ binary is self-contained.
const char* kAgentScript = R"PS1(
# ShieldTier Sandbox Agent — runs inside Windows Sandbox
# Monitors process creation, file changes, registry modifications, and
# network connections.  Writes JSON-line events to the results folder.

param(
    [string]$SamplesDir = "C:\Samples",
    [string]$ResultsDir = "C:\Results"
)

$ErrorActionPreference = "SilentlyContinue"

# -----------------------------------------------------------------
# Wait for sample file to appear (host may still be writing)
# -----------------------------------------------------------------
$waitMax = 10
$waitElapsed = 0
while ($waitElapsed -lt $waitMax) {
    $found = Get-ChildItem -Path $SamplesDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "agent.ps1" -and $_.Name -ne "agent_config.json" -and $_.Name -ne "boot.ps1" -and $_.Name -ne "boot.cmd" -and $_.Name -ne "sandbox_config.json" }
    if ($found) { break }
    Start-Sleep -Seconds 1
    $waitElapsed++
}

# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------
function Write-Event {
    param([hashtable]$Event)
    $Event["timestamp"] = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    $line = $Event | ConvertTo-Json -Compress -Depth 5
    $outFile = Join-Path $ResultsDir "events.jsonl"
    Add-Content -Path $outFile -Value $line -Encoding UTF8
}

function Write-AgentMessage {
    param([string]$Type, [hashtable]$Payload = @{})
    $msg = @{
        type      = $Type
        payload   = $Payload
        timestamp = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    }
    $line = $msg | ConvertTo-Json -Compress -Depth 5
    $outFile = Join-Path $ResultsDir "messages.jsonl"
    Add-Content -Path $outFile -Value $line -Encoding UTF8
}

# -----------------------------------------------------------------
# Signal ready
# -----------------------------------------------------------------
if (-not (Test-Path $ResultsDir)) { New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null }
Write-AgentMessage -Type "ready"

# -----------------------------------------------------------------
# Baseline: snapshot running processes, files, registry run keys
# -----------------------------------------------------------------
$baselineProcesses = @(Get-Process | Select-Object -ExpandProperty Id)
$baselineServices  = @(Get-Service | Select-Object -ExpandProperty Name)

# -----------------------------------------------------------------
# Execute the sample
# -----------------------------------------------------------------
$sample = Get-ChildItem -Path $SamplesDir -File | Where-Object { $_.Name -ne "agent.ps1" -and $_.Name -ne "agent_config.json" -and $_.Name -ne "boot.ps1" -and $_.Name -ne "boot.cmd" -and $_.Name -ne "sandbox_config.json" } | Select-Object -First 1

if ($sample) {
    Write-AgentMessage -Type "sample_received" -Payload @{ filename = $sample.Name; size = $sample.Length }

    $ext = $sample.Extension.ToLower()
    $samplePath = $sample.FullName

    try {
        switch ($ext) {
            ".exe" {
                $proc = Start-Process -FilePath $samplePath -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
            ".dll" {
                $proc = Start-Process -FilePath "rundll32.exe" -ArgumentList "$samplePath,DllMain" -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
            ".ps1" {
                $proc = Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$samplePath`"" -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
            ".bat" {
                $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$samplePath`"" -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
            ".vbs" {
                $proc = Start-Process -FilePath "wscript.exe" -ArgumentList "`"$samplePath`"" -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
            ".js" {
                $proc = Start-Process -FilePath "wscript.exe" -ArgumentList "`"$samplePath`"" -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
            ".msi" {
                $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$samplePath`" /quiet /norestart" -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 10
            }
            default {
                # Try to open with default handler
                $proc = Start-Process -FilePath $samplePath -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
        }
    } catch {
        Write-Event @{
            category = "error"
            action   = "execution_failed"
            detail   = $_.Exception.Message
            path     = $samplePath
        }
    }
} else {
    Write-AgentMessage -Type "error" -Payload @{ message = "No sample found in $SamplesDir" }
}

# -----------------------------------------------------------------
# Monitor loop — collect events for up to 120 seconds
# -----------------------------------------------------------------
$monitorDuration = 120
$interval        = 3
$elapsed         = 0

# Registry keys to watch for persistence
$regKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

# Snapshot initial registry values
$baselineReg = @{}
foreach ($key in $regKeys) {
    if (Test-Path $key) {
        $baselineReg[$key] = @(Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Out-String)
    }
}

# File system directories to monitor
$watchDirs = @(
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:SystemRoot\Temp",
    "$env:ProgramData"
)

# Snapshot initial file counts
$baselineFiles = @{}
foreach ($dir in $watchDirs) {
    if (Test-Path $dir) {
        $baselineFiles[$dir] = @(Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    }
}

while ($elapsed -lt $monitorDuration) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval

    # --- Process creation ---
    $currentProcesses = @(Get-Process -ErrorAction SilentlyContinue)
    foreach ($p in $currentProcesses) {
        if ($p.Id -notin $baselineProcesses) {
            $baselineProcesses += $p.Id
            $procPath = try { $p.MainModule.FileName } catch { "" }
            Write-Event @{
                category = "process"
                action   = "create"
                name     = $p.ProcessName
                detail   = $p.ProcessName
                path     = $procPath
                pid      = $p.Id
            }
        }
    }

    # --- New services ---
    $currentServices = @(Get-Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    foreach ($svc in $currentServices) {
        if ($svc -notin $baselineServices) {
            $baselineServices += $svc
            Write-Event @{
                category = "registry"
                action   = "modify"
                key      = "HKLM\SYSTEM\CurrentControlSet\Services\$svc"
                detail   = "New service installed: $svc"
            }
        }
    }

    # --- Registry changes ---
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            $current = @(Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Out-String)
            if ($baselineReg[$key] -ne $current) {
                Write-Event @{
                    category = "registry"
                    action   = "modify"
                    key      = $key
                    detail   = "Registry key modified"
                }
                $baselineReg[$key] = $current
            }
        }
    }

    # --- File system changes ---
    foreach ($dir in $watchDirs) {
        if (Test-Path $dir) {
            $currentFiles = @(Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
            $newFiles = $currentFiles | Where-Object { $_ -notin $baselineFiles[$dir] }
            foreach ($f in $newFiles) {
                Write-Event @{
                    category = "file"
                    action   = "create"
                    path     = $f
                    detail   = "New file created"
                }
            }
            $baselineFiles[$dir] = $currentFiles
        }
    }

    # --- Network connections ---
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" -and $_.RemoteAddress -ne "0.0.0.0" }
    foreach ($conn in $connections) {
        Write-Event @{
            category    = "network"
            action      = "connect"
            destination = $conn.RemoteAddress
            port        = $conn.RemotePort
            detail      = "TCP connection to $($conn.RemoteAddress):$($conn.RemotePort)"
            pid         = $conn.OwningProcess
        }
    }

    # --- DNS cache (new entries) ---
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    foreach ($entry in $dnsCache) {
        # We log all DNS entries each cycle; host-side deduplication handles repeats
        Write-Event @{
            category = "network"
            action   = "dns"
            detail   = "DNS query: $($entry.Entry)"
            domain   = $entry.Entry
        }
    }
}

# -----------------------------------------------------------------
# Complete
# -----------------------------------------------------------------
Write-AgentMessage -Type "complete" -Payload @{
    elapsed_seconds = $elapsed
    event_file      = Join-Path $ResultsDir "events.jsonl"
}
)PS1";

}  // namespace

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

WindowsSandbox::WindowsSandbox(const std::string& base_dir)
    : base_dir_(base_dir) {
    std::filesystem::create_directories(base_dir_);
}

WindowsSandbox::~WindowsSandbox() {
    // Best-effort cleanup of any running sessions.
    // Stop reposition threads first (outside lock to avoid deadlock).
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, session] : sessions_) {
#ifdef _WIN32
            if (session.reposition_thread.joinable()) {
                session.reposition_thread.request_stop();
            }
#endif
        }
    }
    // Join reposition threads (they may acquire mutex briefly).
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, session] : sessions_) {
#ifdef _WIN32
            if (session.reposition_thread.joinable()) {
                // jthread destructor auto-joins, but be explicit
                session.reposition_thread = std::jthread{};
            }
#endif
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, session] : sessions_) {
        if (session.state != VmState::kStopped && session.state != VmState::kError) {
#ifdef _WIN32
            // Gracefully close sandbox window first.
            if (session.sandbox_hwnd) {
                HWND hwnd = static_cast<HWND>(session.sandbox_hwnd);
                DWORD_PTR result_unused = 0;
                SendMessageTimeoutA(hwnd, WM_CLOSE, 0, 0,
                                    SMTO_ABORTIFHUNG | SMTO_NOTIMEOUTIFNOTHUNG,
                                    3000, &result_unused);
            }

            if (session.process_handle) {
                TerminateProcess(session.process_handle, 1);
                CloseHandle(session.process_handle);
                session.process_handle = nullptr;
            }

            // Force-kill all sandbox-related processes.
            auto kill = [](const wchar_t* name) {
                std::wstring cmd = L"taskkill /F /IM ";
                cmd += name;
                cmd += L" >nul 2>&1";
                _wsystem(cmd.c_str());
            };
            kill(L"WindowsSandbox.exe");
            kill(L"WindowsSandboxClient.exe");
            kill(L"WindowsSandboxRemoteSession.exe");
            kill(L"WindowsSandboxServer.exe");

            // Fallback: kill vmmem processes.
            _wsystem(L"taskkill /F /FI \"IMAGENAME eq vmmem*\" >nul 2>&1");
#endif
        }
    }
}

// ---------------------------------------------------------------------------
// is_available — check for WindowsSandbox.exe
// ---------------------------------------------------------------------------

bool WindowsSandbox::is_available() {
#ifdef _WIN32
    // Check the standard install location.
    const char* sys_root = std::getenv("SystemRoot");
    if (!sys_root) sys_root = "C:\\Windows";

    std::string path = std::string(sys_root) + "\\System32\\WindowsSandbox.exe";
    return std::filesystem::exists(path);
#else
    return false;
#endif
}

// ---------------------------------------------------------------------------
// launch
// ---------------------------------------------------------------------------

Result<std::string> WindowsSandbox::launch(const VmConfig& config) {
#ifndef _WIN32
    return Error{"Windows Sandbox is only available on Windows", "UNSUPPORTED_PLATFORM"};
#else
    if (!is_available()) {
        return Error{"Windows Sandbox is not installed or not enabled", "SANDBOX_UNAVAILABLE"};
    }

    auto session_id = generate_id();
    auto session_dir = base_dir_ + "\\" + session_id;
    auto samples_dir = session_dir + "\\samples";
    auto results_dir = session_dir + "\\results";

    std::filesystem::create_directories(samples_dir);
    std::filesystem::create_directories(results_dir);

    // Deploy the agent script into the samples folder.
    auto deploy_result = deploy_agent(samples_dir);
    if (!deploy_result.ok()) {
        std::filesystem::remove_all(session_dir);
        return Error{deploy_result.error().message, deploy_result.error().code};
    }

    // Generate the .wsb config.
    auto wsb_content = generate_wsb_config(samples_dir, results_dir,
                                           config.enable_network);
    auto wsb_path = session_dir + "\\session.wsb";

    {
        std::ofstream out(wsb_path);
        if (!out) {
            std::filesystem::remove_all(session_dir);
            return Error{"Failed to write .wsb config", "WRITE_FAILED"};
        }
        out << wsb_content;
    }

    // Launch WindowsSandbox.exe with the .wsb file.
    std::string cmd_line = "WindowsSandbox.exe \"" + wsb_path + "\"";

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(nullptr, cmd_line.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        std::filesystem::remove_all(session_dir);
        return Error{"Failed to launch WindowsSandbox.exe (error " +
                         std::to_string(GetLastError()) + ")",
                     "LAUNCH_FAILED"};
    }

    // We don't need the thread handle.
    CloseHandle(pi.hThread);

    Session session;
    session.id = session_id;
    session.state = VmState::kBooting;
    session.config = config;
    session.session_dir = session_dir;
    session.samples_dir = samples_dir;
    session.results_dir = results_dir;
    session.wsb_path = wsb_path;
    session.process_handle = pi.hProcess;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_[session_id] = std::move(session);
    }

    // Wait for the agent to signal readiness (up to 60 seconds).
    auto ready = wait_for_ready(results_dir, 60000);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            it->second.state = ready.ok() ? VmState::kReady : VmState::kError;
        }
    }

    if (!ready.ok()) {
        return Error{"Sandbox agent did not become ready: " + ready.error().message,
                     "BOOT_TIMEOUT"};
    }

    return session_id;
#endif  // _WIN32
}

// ---------------------------------------------------------------------------
// prepare_session — stage sample + agent before launching sandbox
// ---------------------------------------------------------------------------

Result<std::string> WindowsSandbox::prepare_session(
    const FileBuffer& file, bool enable_networking,
    const std::string& network_mode) {
#ifndef _WIN32
    (void)file; (void)enable_networking; (void)network_mode;
    return Error{"Windows Sandbox is only available on Windows", "UNSUPPORTED_PLATFORM"};
#else
    if (!is_available()) {
        return Error{"Windows Sandbox is not installed or not enabled", "SANDBOX_UNAVAILABLE"};
    }

    auto session_id = generate_id();
    auto session_dir = base_dir_ + "\\" + session_id;
    auto samples_dir = session_dir + "\\samples";
    auto results_dir = session_dir + "\\results";

    std::filesystem::create_directories(samples_dir);
    std::filesystem::create_directories(results_dir);

    // Deploy the agent script.
    auto deploy_result = deploy_agent(samples_dir);
    if (!deploy_result.ok()) {
        std::filesystem::remove_all(session_dir);
        return Error{deploy_result.error().message, deploy_result.error().code};
    }

    // Write sandbox config (tells boot.ps1 whether to use INetSim mode).
    {
        auto config_path = samples_dir + "\\sandbox_config.json";
        std::ofstream cfg(config_path);
        if (cfg) {
            cfg << "{\"network_mode\":\"" << network_mode << "\"}";
        }
    }

    // Write the sample file into samples_dir NOW, before launch.
    auto safe_name = std::filesystem::path(file.filename).filename().string();
    if (safe_name.empty() || safe_name == "." || safe_name == "..") {
        safe_name = "sample.bin";
    }
    auto sample_path = samples_dir + "\\" + safe_name;

    {
        std::ofstream out(sample_path, std::ios::binary);
        if (!out) {
            std::filesystem::remove_all(session_dir);
            return Error{"Failed to write sample to session dir", "WRITE_FAILED"};
        }
        out.write(reinterpret_cast<const char*>(file.data.data()),
                  static_cast<std::streamsize>(file.data.size()));
    }

    // Generate the .wsb config.
    auto wsb_content = generate_wsb_config(samples_dir, results_dir,
                                           enable_networking);
    auto wsb_path = session_dir + "\\session.wsb";
    {
        std::ofstream out(wsb_path);
        if (!out) {
            std::filesystem::remove_all(session_dir);
            return Error{"Failed to write .wsb config", "WRITE_FAILED"};
        }
        out << wsb_content;
    }

    // Create the session record (not yet running).
    Session session;
    session.id = session_id;
    session.state = VmState::kStopped;
    session.session_dir = session_dir;
    session.samples_dir = samples_dir;
    session.results_dir = results_dir;
    session.wsb_path = wsb_path;

    VmConfig cfg;
    cfg.platform = VmPlatform::kWindows;
    cfg.enable_network = enable_networking;
    session.config = cfg;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_[session_id] = std::move(session);
    }

    fprintf(stderr, "[ShieldTier] prepare_session: id=%s sample='%s' staged\n",
            session_id.c_str(), safe_name.c_str());
    return session_id;
#endif
}

// ---------------------------------------------------------------------------
// launch (prepared session)
// ---------------------------------------------------------------------------

Result<std::string> WindowsSandbox::launch(
    const std::string& prepared_session_id,
    const VmConfig& config) {
#ifndef _WIN32
    (void)prepared_session_id; (void)config;
    return Error{"Windows Sandbox is only available on Windows", "UNSUPPORTED_PLATFORM"};
#else
    std::string wsb_path;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(prepared_session_id);
        if (it == sessions_.end()) {
            return Error{"Prepared session not found: " + prepared_session_id, "NOT_FOUND"};
        }
        wsb_path = it->second.wsb_path;
        it->second.config = config;
        it->second.state = VmState::kBooting;
    }

    // Launch WindowsSandbox.exe with the .wsb file.
    std::string cmd_line = "WindowsSandbox.exe \"" + wsb_path + "\"";

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(nullptr, cmd_line.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(prepared_session_id);
        if (it != sessions_.end()) it->second.state = VmState::kError;
        return Error{"Failed to launch WindowsSandbox.exe (error " +
                         std::to_string(GetLastError()) + ")",
                     "LAUNCH_FAILED"};
    }

    CloseHandle(pi.hThread);

    std::string results_dir;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(prepared_session_id);
        if (it != sessions_.end()) {
            it->second.process_handle = pi.hProcess;
            results_dir = it->second.results_dir;
        }
    }

    // Don't wait for agent ready — the sandbox needs time to boot and
    // the agent may not run immediately.  The worker thread will wait
    // for the sandbox IP instead (written by boot.ps1 quickly) and then
    // connect RDP.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(prepared_session_id);
        if (it != sessions_.end()) {
            it->second.state = VmState::kReady;
        }
    }

    fprintf(stderr, "[ShieldTier] launch() returned immediately for %s\n",
            prepared_session_id.c_str());
    return prepared_session_id;
#endif
}

// ---------------------------------------------------------------------------
// submit_sample
// ---------------------------------------------------------------------------

Result<VmAnalysisResult> WindowsSandbox::submit_sample(
    const std::string& session_id,
    const FileBuffer& file,
    int timeout_seconds) {
#ifndef _WIN32
    (void)session_id; (void)file; (void)timeout_seconds;
    return Error{"Windows Sandbox is only available on Windows", "UNSUPPORTED_PLATFORM"};
#else
    std::string samples_dir, results_dir;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return Error{"Session not found: " + session_id, "NOT_FOUND"};
        }
        if (it->second.state != VmState::kReady) {
            return Error{"Session not ready for analysis", "INVALID_STATE"};
        }
        it->second.state = VmState::kAnalyzing;
        samples_dir = it->second.samples_dir;
        results_dir = it->second.results_dir;
    }

    auto start = std::chrono::steady_clock::now();

    // Write sample to the shared samples folder (skip if already staged
    // via prepare_session — indicated by empty file data).
    if (!file.data.empty()) {
        auto safe_name = std::filesystem::path(file.filename).filename().string();
        if (safe_name.empty() || safe_name == "." || safe_name == "..") {
            safe_name = "sample.bin";
        }
        auto sample_path = samples_dir + "\\" + safe_name;

        {
            std::ofstream out(sample_path, std::ios::binary);
            if (!out) {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = sessions_.find(session_id);
                if (it != sessions_.end()) it->second.state = VmState::kReady;
                return Error{"Failed to write sample to shared folder", "WRITE_FAILED"};
            }
            out.write(reinterpret_cast<const char*>(file.data.data()),
                      static_cast<std::streamsize>(file.data.size()));
        }
    }

    // Poll the results directory for events until timeout.
    int elapsed = 0;
    while (elapsed < timeout_seconds) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ++elapsed;

        // Check if the sandbox process is still running.
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) break;

            DWORD exit_code = STILL_ACTIVE;
            if (it->second.process_handle) {
                GetExitCodeProcess(it->second.process_handle, &exit_code);
            }
            if (exit_code != STILL_ACTIVE) break;
        }

        // Check if agent signaled completion.
        auto messages_path = results_dir + "\\messages.jsonl";
        if (std::filesystem::exists(messages_path)) {
            std::ifstream in(messages_path);
            std::string content((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
            if (content.find("\"complete\"") != std::string::npos) {
                break;
            }
        }
    }

    auto end = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();

    // Collect events.
    auto events_result = collect_events(results_dir);

    VmAnalysisResult result;
    result.vm_id = session_id;
    result.duration_ms = duration;

    if (events_result.ok()) {
        result.success = true;
        result.events = std::move(events_result.value());
    } else {
        result.success = false;
        result.error = events_result.error().message;
    }

    // Collect network events into network_activity summary.
    json net = json::object();
    json dns_queries = json::array();
    json connections = json::array();

    if (result.success) {
        for (const auto& ev : result.events) {
            if (!ev.is_object()) continue;
            auto cat = ev.value("category", "");
            auto act = ev.value("action", "");

            if (cat == "network" && act == "dns") {
                dns_queries.push_back({{"domain", ev.value("domain", "")}});
            } else if (cat == "network" && act == "connect") {
                connections.push_back({
                    {"destination", ev.value("destination", "")},
                    {"port", ev.value("port", 0)}
                });
            }
        }
    }
    net["dns_queries"] = std::move(dns_queries);
    net["connections"] = std::move(connections);
    result.network_activity = std::move(net);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            it->second.state = VmState::kReady;
        }
    }

    return result;
#endif  // _WIN32
}

// ---------------------------------------------------------------------------
// stop
// ---------------------------------------------------------------------------

Result<bool> WindowsSandbox::stop(const std::string& session_id) {
#ifndef _WIN32
    (void)session_id;
    return Error{"Windows Sandbox is only available on Windows", "UNSUPPORTED_PLATFORM"};
#else
    // Stop reposition thread first (must happen before taking the lock if
    // the thread itself tries to read sessions_ under the lock).
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return Error{"Session not found: " + session_id, "NOT_FOUND"};
        }
        if (it->second.reposition_thread.joinable()) {
            it->second.reposition_thread.request_stop();
        }
    }
    // Let the thread finish (jthread auto-joins on reassignment).
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            it->second.reposition_thread = std::jthread{};
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return Error{"Session not found: " + session_id, "NOT_FOUND"};
    }

    auto& session = it->second;

    // 1. Graceful close via WM_CLOSE.
    if (session.sandbox_hwnd) {
        HWND hwnd = static_cast<HWND>(session.sandbox_hwnd);
        DWORD_PTR result_unused = 0;
        SendMessageTimeoutA(hwnd, WM_CLOSE, 0, 0,
                            SMTO_ABORTIFHUNG | SMTO_NOTIMEOUTIFNOTHUNG,
                            3000, &result_unused);
        session.sandbox_hwnd = nullptr;
    }

    // 2. Terminate the process we launched.
    if (session.process_handle) {
        TerminateProcess(session.process_handle, 0);
        CloseHandle(session.process_handle);
        session.process_handle = nullptr;
    }

    // 3. Force-kill all sandbox-related processes.
    auto kill = [](const wchar_t* name) {
        std::wstring cmd = L"taskkill /F /IM ";
        cmd += name;
        cmd += L" >nul 2>&1";
        _wsystem(cmd.c_str());
    };
    kill(L"WindowsSandbox.exe");
    kill(L"WindowsSandboxClient.exe");
    kill(L"WindowsSandboxRemoteSession.exe");
    kill(L"WindowsSandboxServer.exe");

    // 4. Fallback: kill vmmem.
    _wsystem(L"taskkill /F /FI \"IMAGENAME eq vmmem*\" >nul 2>&1");

    std::error_code ec;
    std::filesystem::remove_all(session.session_dir, ec);

    session.state = VmState::kStopped;
    return true;
#endif
}

// ---------------------------------------------------------------------------
// is_running / get_state / list_sessions
// ---------------------------------------------------------------------------

bool WindowsSandbox::is_running(const std::string& session_id) const {
#ifdef _WIN32
    // The launcher (WindowsSandbox.exe) exits immediately after starting
    // the VM, so checking its process handle is unreliable.  Instead,
    // check whether WindowsSandboxServer.exe is still alive — it persists
    // for the lifetime of the sandbox VM.
    (void)session_id;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"WindowsSandboxServer.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
#else
    (void)session_id;
    return false;
#endif
}

std::string WindowsSandbox::get_results_dir(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return "";
    return it->second.results_dir;
}

VmState WindowsSandbox::get_state(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return VmState::kStopped;
    return it->second.state;
}

std::vector<VmInstance> WindowsSandbox::list_sessions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<VmInstance> result;
    result.reserve(sessions_.size());
    for (const auto& [id, s] : sessions_) {
        VmInstance vi;
        vi.id = s.id;
        vi.state = s.state;
        vi.config = s.config;
        result.push_back(std::move(vi));
    }
    return result;
}

// ---------------------------------------------------------------------------
// embed_in_window / resize_embedded — reparent sandbox into ShieldTier
// ---------------------------------------------------------------------------

Result<bool> WindowsSandbox::embed_in_window(
    const std::string& session_id,
    void* parent_hwnd, int x, int y, int w, int h) {
#ifndef _WIN32
    (void)session_id; (void)parent_hwnd; (void)x; (void)y; (void)w; (void)h;
    return Error{"Windows Sandbox is only available on Windows", "UNSUPPORTED_PLATFORM"};
#else
    if (!parent_hwnd) {
        return Error{"parent_hwnd is null", "INVALID_PARAM"};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return Error{"Session not found: " + session_id, "NOT_FOUND"};
    }

    auto& session = it->second;
    HWND sandbox_hwnd = static_cast<HWND>(session.sandbox_hwnd);

    if (!sandbox_hwnd) {
        // Find the Windows Sandbox window.
        struct FindData {
            HWND result = nullptr;
        } fd;

        // Method 1: FindWindow by exact title
        sandbox_hwnd = FindWindowA(nullptr, "Windows Sandbox");
        fprintf(stderr, "[ShieldTier] FindWindowA('Windows Sandbox') = %p\n",
                static_cast<void*>(sandbox_hwnd));

        // Method 2: Enumerate all top-level windows
        if (!sandbox_hwnd) {
            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                auto* data = reinterpret_cast<FindData*>(lParam);
                char title[256] = {};
                GetWindowTextA(hwnd, title, sizeof(title));
                if (strstr(title, "Windows Sandbox") && IsWindowVisible(hwnd)) {
                    data->result = hwnd;
                    fprintf(stderr, "[ShieldTier] EnumWindows found: '%s' HWND=%p\n",
                            title, static_cast<void*>(hwnd));
                    return FALSE;
                }
                return TRUE;
            }, reinterpret_cast<LPARAM>(&fd));
            sandbox_hwnd = fd.result;
        }

        if (!sandbox_hwnd) {
            fprintf(stderr, "[ShieldTier] embed_in_window: sandbox window not found\n");
            return Error{"Could not find Windows Sandbox window", "WINDOW_NOT_FOUND"};
        }

        session.original_style = GetWindowLongA(sandbox_hwnd, GWL_STYLE);
        session.original_exstyle = GetWindowLongA(sandbox_hwnd, GWL_EXSTYLE);
        session.sandbox_hwnd = sandbox_hwnd;
    }

    HWND owner = static_cast<HWND>(parent_hwnd);
    session.owner_hwnd = parent_hwnd;

    // --- Owned window approach (NOT SetParent/WS_CHILD) ---
    // Windows Sandbox uses an internal RDP session. SetParent + WS_CHILD
    // breaks the RDP pipeline causing a freeze at splash.  Instead we:
    //   1. Strip decorations only (caption, thick frame, sysmenu)
    //   2. Do NOT add WS_CHILD
    //   3. Add WS_EX_TOOLWINDOW to hide from taskbar
    //   4. Set owner via GWLP_HWNDPARENT (not SetParent)
    //   5. Position using screen coordinates
    //   6. Run a reposition thread to track owner movement

    // 1. Remove decorations — keep WS_VISIBLE, WS_CLIPCHILDREN, WS_CLIPSIBLINGS.
    LONG style = GetWindowLongA(sandbox_hwnd, GWL_STYLE);
    style &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX |
                WS_MAXIMIZEBOX | WS_SYSMENU | WS_OVERLAPPEDWINDOW);
    style |= WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
    // Do NOT set WS_CHILD — this is the critical difference.
    SetWindowLongA(sandbox_hwnd, GWL_STYLE, style);

    // 2. Add WS_EX_TOOLWINDOW (hides from taskbar), remove WS_EX_APPWINDOW.
    LONG exstyle = GetWindowLongA(sandbox_hwnd, GWL_EXSTYLE);
    exstyle &= ~(WS_EX_APPWINDOW | WS_EX_WINDOWEDGE | WS_EX_DLGMODALFRAME);
    exstyle |= WS_EX_TOOLWINDOW;
    SetWindowLongA(sandbox_hwnd, GWL_EXSTYLE, exstyle);

    // 3. Set owner (not parent) — sandbox stays on top of ShieldTier.
    SetWindowLongPtrA(sandbox_hwnd, GWLP_HWNDPARENT,
                      reinterpret_cast<LONG_PTR>(owner));

    // 4. Convert parent-relative coords to screen coords and position.
    POINT screen_pt = {x, y};
    ClientToScreen(owner, &screen_pt);
    SetWindowPos(sandbox_hwnd, HWND_TOP,
                 screen_pt.x, screen_pt.y, w, h,
                 SWP_FRAMECHANGED | SWP_SHOWWINDOW | SWP_NOACTIVATE);

    fprintf(stderr, "[ShieldTier] Embedded (owned) sandbox HWND=%p owner=%p at screen(%ld,%ld) %dx%d\n",
            static_cast<void*>(sandbox_hwnd), parent_hwnd,
            screen_pt.x, screen_pt.y, w, h);

    // 5. Start reposition thread — tracks owner position every 100ms.
    //    Also hides sandbox when ShieldTier is minimized.
    if (session.reposition_thread.joinable()) {
        session.reposition_thread.request_stop();
        session.reposition_thread = std::jthread{};
    }

    HWND sbx = sandbox_hwnd;
    int rel_x = x, rel_y = y, rel_w = w, rel_h = h;

    session.reposition_thread = std::jthread(
        [sbx, owner, rel_x, rel_y, rel_w, rel_h](std::stop_token stop) {
            while (!stop.stop_requested()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

                if (!IsWindow(sbx) || !IsWindow(owner)) break;

                // Hide sandbox when owner is minimized.
                if (IsIconic(owner)) {
                    if (IsWindowVisible(sbx)) {
                        ShowWindow(sbx, SW_HIDE);
                    }
                    continue;
                }

                // Show sandbox if it was hidden due to minimize.
                if (!IsWindowVisible(sbx)) {
                    ShowWindow(sbx, SW_SHOWNOACTIVATE);
                }

                // Reposition to track owner.
                POINT pt = {rel_x, rel_y};
                ClientToScreen(owner, &pt);
                SetWindowPos(sbx, HWND_TOP,
                             pt.x, pt.y, rel_w, rel_h,
                             SWP_NOACTIVATE | SWP_NOZORDER);
            }
        });

    return true;
#endif
}

Result<bool> WindowsSandbox::resize_embedded(
    const std::string& session_id, int x, int y, int w, int h) {
#ifndef _WIN32
    (void)session_id; (void)x; (void)y; (void)w; (void)h;
    return Error{"Windows Sandbox is only available on Windows", "UNSUPPORTED_PLATFORM"};
#else
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return Error{"Session not found", "NOT_FOUND"};
    }

    auto& session = it->second;
    HWND sandbox_hwnd = static_cast<HWND>(session.sandbox_hwnd);
    if (!sandbox_hwnd) {
        return Error{"Sandbox window not embedded yet", "NOT_EMBEDDED"};
    }

    // Restart reposition thread with new dimensions.
    if (session.reposition_thread.joinable()) {
        session.reposition_thread.request_stop();
        session.reposition_thread = std::jthread{};
    }

    HWND owner = static_cast<HWND>(session.owner_hwnd);

    // Position now using screen coords.
    if (owner) {
        POINT pt = {x, y};
        ClientToScreen(owner, &pt);
        SetWindowPos(sandbox_hwnd, HWND_TOP, pt.x, pt.y, w, h,
                     SWP_SHOWWINDOW | SWP_NOACTIVATE);
    } else {
        SetWindowPos(sandbox_hwnd, HWND_TOP, x, y, w, h,
                     SWP_SHOWWINDOW | SWP_NOACTIVATE);
    }

    // Restart reposition thread with updated coords.
    if (owner) {
        HWND sbx = sandbox_hwnd;
        session.reposition_thread = std::jthread(
            [sbx, owner, x, y, w, h](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if (!IsWindow(sbx) || !IsWindow(owner)) break;

                    if (IsIconic(owner)) {
                        if (IsWindowVisible(sbx)) ShowWindow(sbx, SW_HIDE);
                        continue;
                    }
                    if (!IsWindowVisible(sbx)) {
                        ShowWindow(sbx, SW_SHOWNOACTIVATE);
                    }

                    POINT pt = {x, y};
                    ClientToScreen(owner, &pt);
                    SetWindowPos(sbx, HWND_TOP, pt.x, pt.y, w, h,
                                 SWP_NOACTIVATE | SWP_NOZORDER);
                }
            });
    }

    return true;
#endif
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

std::string WindowsSandbox::generate_wsb_config(
    const std::string& samples_dir,
    const std::string& results_dir,
    bool enable_networking) const {
    std::ostringstream xml;
    xml << "<Configuration>\n"
        << "  <MappedFolders>\n"
        << "    <MappedFolder>\n"
        << "      <HostFolder>" << samples_dir << "</HostFolder>\n"
        << "      <SandboxFolder>C:\\Samples</SandboxFolder>\n"
        << "      <ReadOnly>false</ReadOnly>\n"
        << "    </MappedFolder>\n"
        << "    <MappedFolder>\n"
        << "      <HostFolder>" << results_dir << "</HostFolder>\n"
        << "      <SandboxFolder>C:\\Results</SandboxFolder>\n"
        << "      <ReadOnly>false</ReadOnly>\n"
        << "    </MappedFolder>\n"
        << "  </MappedFolders>\n"
        << "  <LogonCommand>\n"
        << "    <Command>C:\\Samples\\boot.cmd</Command>\n"
        << "  </LogonCommand>\n"
        << "  <Networking>" << (enable_networking ? "Enable" : "Disable") << "</Networking>\n"
        << "  <MemoryInMB>2048</MemoryInMB>\n"
        << "</Configuration>\n";
    return xml.str();
}

Result<bool> WindowsSandbox::deploy_agent(const std::string& samples_dir) const {
    auto agent_path = samples_dir +
#ifdef _WIN32
        "\\agent.ps1";
#else
        "/agent.ps1";
#endif

    std::ofstream out(agent_path);
    if (!out) {
        return Error{"Failed to write agent script", "WRITE_FAILED"};
    }
    out << kAgentScript;
    out.close();

    if (!out.good()) {
        return Error{"I/O error writing agent script", "WRITE_FAILED"};
    }

    // Write boot.cmd — .cmd files have NO execution policy restrictions.
    // This is the actual LogonCommand target.  It invokes boot.ps1 via
    // powershell with -ExecutionPolicy Bypass.
    auto cmd_path = samples_dir +
#ifdef _WIN32
        "\\boot.cmd";
#else
        "/boot.cmd";
#endif

    static const char* kBootCmd =
        "@echo off\r\n"
        "mkdir C:\\Results 2>nul\r\n"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Samples\\boot.ps1 >> C:\\Results\\boot.log 2>&1\r\n";

    {
        std::ofstream cmd_out(cmd_path);
        if (cmd_out) {
            cmd_out << kBootCmd;
            cmd_out.close();
        }
    }

    // Write boot.ps1 — runs at LogonCommand (via boot.cmd), enables RDP,
    // writes IP, configures firewall for INet mode, then launches the agent.
    auto boot_path = samples_dir +
#ifdef _WIN32
        "\\boot.ps1";
#else
        "/boot.ps1";
#endif

    static const char* kBootScript = R"PS1(
# ShieldTier Sandbox Boot Script
if (!(Test-Path C:\Results)) { mkdir C:\Results -Force | Out-Null }

# Write sandbox IP
try {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        ? { $_.IPAddress -ne '127.0.0.1' } | Select -First 1).IPAddress
    if ($ip) { [IO.File]::WriteAllText('C:\Results\sandbox_ip.txt', $ip) }
} catch {}

# Read config (written by host before launch)
$cfg = @{}
if (Test-Path C:\Samples\sandbox_config.json) {
    try { $cfg = Get-Content C:\Samples\sandbox_config.json -Raw | ConvertFrom-Json } catch {}
}

# Network mode is controlled at the Hyper-V level via <Networking> in the WSB config.
# INet (Fake) mode uses <Networking>Disable</Networking> — no TCP/IP at all.
# Internet (Real) mode uses <Networking>Enable</Networking> — full internet.
# Mapped folders (C:\Samples, C:\Results) always work regardless (VMBus, not TCP/IP).
if ($cfg.network_mode -eq 'inetsim') {
    [IO.File]::WriteAllText('C:\Results\network_mode.txt', 'isolated')
} else {
    [IO.File]::WriteAllText('C:\Results\network_mode.txt', 'internet')
}

[IO.File]::WriteAllText('C:\Results\boot_ok.txt', 'done')

# Run agent
& 'C:\Samples\agent.ps1' -SamplesDir 'C:\Samples' -ResultsDir 'C:\Results'
)PS1";

    std::ofstream boot_out(boot_path);
    if (boot_out) {
        boot_out << kBootScript;
        boot_out.close();
    }

    return true;
}

Result<std::vector<json>> WindowsSandbox::collect_events(
    const std::string& results_dir) const {
    std::vector<json> events;

    // Read the events.jsonl file (JSON lines format).
    auto events_path = results_dir +
#ifdef _WIN32
        "\\events.jsonl";
#else
        "/events.jsonl";
#endif

    if (!std::filesystem::exists(events_path)) {
        return events;  // No events yet — not an error.
    }

    std::ifstream in(events_path);
    if (!in) {
        return Error{"Failed to read events file", "READ_FAILED"};
    }

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        try {
            events.push_back(json::parse(line));
        } catch (const json::parse_error&) {
            // Skip malformed lines.
        }
    }

    return events;
}

Result<bool> WindowsSandbox::wait_for_ready(
    const std::string& results_dir, int timeout_ms) const {
    auto messages_path = results_dir +
#ifdef _WIN32
        "\\messages.jsonl";
#else
        "/messages.jsonl";
#endif

    int elapsed = 0;
    while (elapsed < timeout_ms) {
        if (std::filesystem::exists(messages_path)) {
            std::ifstream in(messages_path);
            std::string content((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
            if (content.find("\"ready\"") != std::string::npos) {
                return true;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        elapsed += 500;
    }

    return Error{"Agent did not signal ready within timeout", "TIMEOUT"};
}

std::string WindowsSandbox::generate_session_id() const {
    return generate_id();
}

// ---------------------------------------------------------------------------
// get_sandbox_ip — read IP written by LogonCommand
// ---------------------------------------------------------------------------

std::string WindowsSandbox::get_sandbox_ip(
    const std::string& results_dir, int timeout_ms) const {
    auto ip_path = results_dir +
#ifdef _WIN32
        "\\sandbox_ip.txt";
#else
        "/sandbox_ip.txt";
#endif

    int elapsed = 0;
    while (elapsed < timeout_ms) {
        if (std::filesystem::exists(ip_path)) {
            std::ifstream in(ip_path);
            std::string ip;
            std::getline(in, ip);
            // Trim whitespace
            while (!ip.empty() && (ip.back() == '\r' || ip.back() == '\n' ||
                                   ip.back() == ' '))
                ip.pop_back();
            if (!ip.empty()) {
                fprintf(stderr, "[ShieldTier] Sandbox IP: %s\n", ip.c_str());
                return ip;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        elapsed += 500;
    }
    return "";
}

// ---------------------------------------------------------------------------
// connect_rdp — create MsRdpClient ActiveX inside parent_hwnd
// ---------------------------------------------------------------------------

Result<bool> WindowsSandbox::connect_rdp(
    const std::string& session_id, void* parent_hwnd,
    int x, int y, int w, int h) {
#ifndef _WIN32
    (void)session_id; (void)parent_hwnd; (void)x; (void)y; (void)w; (void)h;
    return Error{"RDP client only available on Windows", "UNSUPPORTED_PLATFORM"};
#else
    std::string results_dir;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return Error{"Session not found", "NOT_FOUND"};
        }
        results_dir = it->second.results_dir;
    }

    // Wait for sandbox to write its IP address.
    std::string sandbox_ip = get_sandbox_ip(results_dir, 30000);
    if (sandbox_ip.empty()) {
        return Error{"Could not determine sandbox IP", "NO_IP"};
    }

    // Create RDP client.
    auto rdp = std::make_unique<RdpClient>();
    auto create_result = rdp->create(parent_hwnd, x, y, w, h);
    if (!create_result.ok()) {
        return Error{create_result.error().message, create_result.error().code};
    }

    // Connect to sandbox RDP.
    auto connect_result = rdp->connect(
        sandbox_ip, 3389, "WDAGUtilityAccount", "Sh!3ldT13r#RDP");
    if (!connect_result.ok()) {
        rdp->destroy();
        return Error{connect_result.error().message, connect_result.error().code};
    }

    // Minimize the standalone sandbox window — don't hide it until RDP
    // has rendered at least one frame.  Minimizing keeps it out of the way
    // without breaking the internal RDP session.
    HWND sandbox_hwnd = FindWindowA(nullptr, "Windows Sandbox");
    if (sandbox_hwnd) {
        ShowWindow(sandbox_hwnd, SW_MINIMIZE);
        fprintf(stderr, "[ShieldTier] Minimized standalone sandbox window\n");
    }

    // Store in session.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            it->second.rdp_client = std::move(rdp);
        }
    }

    fprintf(stderr, "[ShieldTier] RDP connected to sandbox at %s:3389\n",
            sandbox_ip.c_str());
    return true;
#endif
}

void WindowsSandbox::resize_rdp(const std::string& session_id,
                                 int x, int y, int w, int h) {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end() && it->second.rdp_client) {
        it->second.rdp_client->resize(x, y, w, h);
    }
#endif
}

}  // namespace shieldtier
