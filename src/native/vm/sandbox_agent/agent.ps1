# ShieldTier Sandbox Agent — runs inside Windows Sandbox
# Monitors process creation, file changes, registry modifications, and
# network connections.  Writes JSON-line events to the results folder.

param(
    [string]$SamplesDir = "C:\Samples",
    [string]$ResultsDir = "C:\Results"
)

$ErrorActionPreference = "SilentlyContinue"

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
$sample = Get-ChildItem -Path $SamplesDir -File | Where-Object { $_.Name -ne "agent.ps1" -and $_.Name -ne "agent_config.json" } | Select-Object -First 1

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
            Write-Event @{
                category = "process"
                action   = "create"
                name     = $p.ProcessName
                detail   = $p.ProcessName
                path     = try { $p.MainModule.FileName } catch { "" }
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
