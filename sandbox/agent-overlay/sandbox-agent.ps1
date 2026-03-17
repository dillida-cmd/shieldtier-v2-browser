# ShieldTier Windows Sandbox Agent v1.0
# Runs inside Windows VM, monitors samples directory, executes + captures behavior.
# Install: Copy to C:\ShieldTier\ and add to Startup.

$ErrorActionPreference = "SilentlyContinue"
$SampleDir = "Z:\samples"        # virtfs mapped drive
$ResultDir = "Z:\results"        # virtfs mapped drive
$AgentLog  = "$ResultDir\agent.log"

function Log($msg) {
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[agent $ts] $msg"
    Write-Host $line
    Add-Content -Path $AgentLog -Value $line
}

# Wait for virtfs mount
for ($i = 0; $i -lt 30; $i++) {
    if (Test-Path $SampleDir) { break }
    Start-Sleep -Seconds 2
}

if (-not (Test-Path $SampleDir)) {
    Write-Host "ERROR: Sample directory not found at $SampleDir"
    exit 1
}

New-Item -ItemType Directory -Path $ResultDir -Force | Out-Null

Log "========================================="
Log "  ShieldTier Windows Sandbox Agent v1.0"
Log "========================================="
Log "Hostname:  $env:COMPUTERNAME"
Log "OS:        $(Get-CimInstance Win32_OperatingSystem | Select-Object -Expand Caption)"
Log "Arch:      $env:PROCESSOR_ARCHITECTURE"
Log "User:      $env:USERNAME"
Log ""

# Baseline
Get-Process | Export-Csv "$ResultDir\baseline_processes.csv" -NoTypeInformation
Get-NetTCPConnection | Export-Csv "$ResultDir\baseline_tcp.csv" -NoTypeInformation
Get-ChildItem -Path "$env:TEMP" -Recurse | Out-File "$ResultDir\baseline_temp.txt"
Log "Baseline captured"

# Process each sample
$samples = Get-ChildItem -Path $SampleDir -File
foreach ($sample in $samples) {
    $name = $sample.Name
    $sDir = "$ResultDir\$name"
    New-Item -ItemType Directory -Path $sDir -Force | Out-Null

    Log ""
    Log "==========================================="
    Log "  Analyzing: $name"
    Log "==========================================="

    # File metadata
    $hash = Get-FileHash -Path $sample.FullName -Algorithm SHA256
    Log "SHA256: $($hash.Hash)"
    $hash | Out-File "$sDir\sha256.txt"

    # PE analysis
    try {
        $pe = [System.Reflection.AssemblyName]::GetAssemblyName($sample.FullName)
        Log "Assembly: $($pe.FullName)"
    } catch {}

    # Strings extraction
    $content = [System.IO.File]::ReadAllBytes($sample.FullName)
    $strings = [System.Text.Encoding]::ASCII.GetString($content) -split '[^\x20-\x7E]+' |
        Where-Object { $_.Length -ge 4 }
    $strings | Out-File "$sDir\strings.txt"
    Log "Strings extracted: $($strings.Count)"

    # IOC extraction
    $urls = $strings | Where-Object { $_ -match 'https?://' }
    $urls | Out-File "$sDir\ioc_urls.txt"
    $ips = $strings | Where-Object { $_ -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' }
    $ips | Out-File "$sDir\ioc_ips.txt"
    Log "URLs: $($urls.Count)  IPs: $($ips.Count)"

    # Pre-execution snapshot
    Get-Process | Export-Csv "$sDir\pre_processes.csv" -NoTypeInformation
    Get-NetTCPConnection | Export-Csv "$sDir\pre_tcp.csv" -NoTypeInformation
    Get-ChildItem "$env:TEMP" -Recurse | Out-File "$sDir\pre_temp.txt"

    # Execute with monitoring
    Log ">>> EXECUTING $name (30s timeout) <<<"
    $tempExe = "$env:TEMP\sample_$name"
    Copy-Item $sample.FullName $tempExe -Force

    # Start Process Monitor (background job captures snapshots)
    $monJob = Start-Job -ScriptBlock {
        param($pid, $outDir)
        $snap = 0
        while ($true) {
            $snap++
            try {
                $proc = Get-Process -Id $pid -ErrorAction Stop
                Get-Process | Export-Csv "$outDir\snap_${snap}_ps.csv" -NoTypeInformation
                Get-NetTCPConnection | Export-Csv "$outDir\snap_${snap}_tcp.csv" -NoTypeInformation
                Get-ChildItem "$env:TEMP" -Recurse | Out-File "$outDir\snap_${snap}_temp.txt"
            } catch { break }
            Start-Sleep -Seconds 2
        }
    }

    # Execute sample
    $proc = Start-Process -FilePath $tempExe -PassThru -NoNewWindow `
        -RedirectStandardOutput "$sDir\stdout.txt" `
        -RedirectStandardError "$sDir\stderr.txt"

    # Update monitor job with PID
    $monJob = Start-Job -ScriptBlock {
        param($procId, $outDir)
        $snap = 0
        for ($i = 0; $i -lt 15; $i++) {
            $snap++
            try {
                Get-Process -Id $procId -ErrorAction Stop | Out-Null
                Get-Process | Export-Csv "$outDir\snap_${snap}_ps.csv" -NoTypeInformation
                Get-NetTCPConnection | Export-Csv "$outDir\snap_${snap}_tcp.csv" -NoTypeInformation
            } catch { break }
            Start-Sleep -Seconds 2
        }
    } -ArgumentList $proc.Id, $sDir

    # Wait up to 30 seconds
    if (-not $proc.WaitForExit(30000)) {
        Log "TIMEOUT - killing process"
        Stop-Process -Id $proc.Id -Force
    }
    $exitCode = $proc.ExitCode
    Log "Exit code: $exitCode"

    Stop-Job $monJob -ErrorAction SilentlyContinue
    Remove-Job $monJob -ErrorAction SilentlyContinue

    # Post-execution diff
    Get-Process | Export-Csv "$sDir\post_processes.csv" -NoTypeInformation
    Get-NetTCPConnection | Export-Csv "$sDir\post_tcp.csv" -NoTypeInformation
    Get-ChildItem "$env:TEMP" -Recurse | Out-File "$sDir\post_temp.txt"

    # Detect new processes
    $prePids = Import-Csv "$sDir\pre_processes.csv" | Select-Object -Expand Id
    $postPids = Import-Csv "$sDir\post_processes.csv" | Select-Object -Expand Id
    $newPids = $postPids | Where-Object { $_ -notin $prePids }
    if ($newPids) {
        Log "NEW PROCESSES: $($newPids -join ', ')"
    }

    # Detect new TCP connections
    $preTcp = Import-Csv "$sDir\pre_tcp.csv" | Select-Object RemoteAddress, RemotePort
    $postTcp = Import-Csv "$sDir\post_tcp.csv" | Select-Object RemoteAddress, RemotePort
    $newTcp = Compare-Object $preTcp $postTcp -Property RemoteAddress, RemotePort |
        Where-Object { $_.SideIndicator -eq "=>" }
    if ($newTcp) {
        Log "NEW TCP CONNECTIONS:"
        $newTcp | ForEach-Object { Log "  $($_.RemoteAddress):$($_.RemotePort)" }
    }

    # Detect new temp files
    $newTemp = Compare-Object `
        (Get-Content "$sDir\pre_temp.txt") `
        (Get-Content "$sDir\post_temp.txt") |
        Where-Object { $_.SideIndicator -eq "=>" }
    if ($newTemp) {
        Log "NEW TEMP FILES:"
        $newTemp | ForEach-Object { Log "  $($_.InputObject)" }
    }

    # Registry snapshot (Run keys)
    try {
        $runKeys = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" 2>$null
        $runKeys | Out-File "$sDir\registry_run.txt"
    } catch {}

    # Stdout
    if (Test-Path "$sDir\stdout.txt") {
        $stdout = Get-Content "$sDir\stdout.txt"
        if ($stdout) {
            Log ""
            Log "=== STDOUT ==="
            $stdout | ForEach-Object { Log "  $_" }
        }
    }

    # Cleanup
    Remove-Item $tempExe -Force -ErrorAction SilentlyContinue
    Log ""
    Log "=== Analysis complete: $name ==="
}

Log ""
Log "========================================="
Log "  All samples processed"
Log "========================================="
