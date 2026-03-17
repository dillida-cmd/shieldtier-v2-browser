rule EICAR_Test_File {
    meta:
        description = "EICAR antivirus test file"
        author = "ShieldTier UAT"
        severity = "critical"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell patterns"
        author = "ShieldTier UAT"
        severity = "high"
        mitre_id = "T1059.001"
    strings:
        $enc1 = "FromBase64String" nocase
        $enc2 = "-EncodedCommand" nocase
        $enc3 = "IEX(" nocase
        $dl1 = "Invoke-WebRequest" nocase
        $dl2 = "Net.WebClient" nocase
        $dl3 = "DownloadString" nocase
    condition:
        any of ($enc*) and any of ($dl*)
}

rule Suspicious_Script_Obfuscation {
    meta:
        description = "Detects common script obfuscation"
        author = "ShieldTier UAT"
        severity = "medium"
    strings:
        $eval_atob = "eval(atob(" nocase
        $char_code = "String.fromCharCode" nocase
        $doc_write = "document.write(" nocase
        $unescape = "unescape(" nocase
    condition:
        2 of them
}
