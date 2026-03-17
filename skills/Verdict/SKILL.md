---
name: Verdict
description: Use when building the threat scoring engine — weighted multi-engine aggregation, MITRE ATT&CK mapping, confidence normalization, heuristic decision trees, and VMProtect-virtualized scoring functions
---

# S10 — Verdict: Scoring Engine

## Overview

Consolidates findings from all analysis engines (S3-S7) into a unified threat score (0-100), verdict (clean/suspicious/malicious), and MITRE ATT&CK technique mapping. The scoring algorithm and heuristics are protected with VMProtect virtualization markers.

## Dependencies

- **Requires:** S3 (YARA), S4 (file analysis), S5 (sandbox/advanced) interfaces — starts parallel but finalizes after they deliver
- **Blocks:** S11 (security protects scoring functions), S12 (cloud serves scoring)

## File Ownership

```
src/native/scoring/
  engine.cpp/.h      (main scoring algorithm — VMProtect marker)
  heuristics.cpp/.h  (detection heuristics — VMProtect marker)
  threat_model.cpp/.h (threat classification, MITRE ATT&CK mapping)
```

## Exit Criteria

Analysis results from all engines → unified threat score (0-100) + verdict + confidence + MITRE techniques. VMProtect markers on critical functions. Consistent output regardless of which engines ran.

---

## Scoring Engine

```cpp
// VMProtectBeginUltra("scoring_engine");

class ScoringEngine {
public:
    ThreatVerdict compute(const std::vector<AnalysisEngineResult>& results) {
        ThreatVerdict verdict;

        // Phase 1: Aggregate findings from all engines
        auto all_findings = aggregate_findings(results);

        // Phase 2: Map findings to MITRE ATT&CK
        verdict.mitre_techniques = map_mitre(all_findings);

        // Phase 3: Compute weighted score
        verdict.threat_score = compute_weighted_score(all_findings, results);

        // Phase 4: Determine verdict and confidence
        auto [v, conf] = classify(verdict.threat_score, all_findings);
        verdict.verdict = v;
        verdict.confidence = conf;
        verdict.risk_level = score_to_risk(verdict.threat_score);
        verdict.findings = std::move(all_findings);

        return verdict;
    }

private:
    // Engine weights — how much each engine contributes to final score
    struct EngineWeight {
        AnalysisEngine engine;
        double weight;
        double reliability;  // 0-1, how often this engine is correct
    };

    static constexpr EngineWeight kWeights[] = {
        {AnalysisEngine::kYara,         0.30, 0.95},
        {AnalysisEngine::kFileAnalysis, 0.15, 0.85},
        {AnalysisEngine::kSandbox,      0.25, 0.90},
        {AnalysisEngine::kAdvanced,     0.15, 0.88},
        {AnalysisEngine::kEnrichment,   0.10, 0.92},
        {AnalysisEngine::kContent,      0.05, 0.80},
    };

    int compute_weighted_score(const std::vector<Finding>& findings,
                                const std::vector<AnalysisEngineResult>& results) {
        double total_score = 0.0;
        double total_weight = 0.0;

        for (auto& w : kWeights) {
            // Find this engine's result
            auto it = std::find_if(results.begin(), results.end(),
                [&](const AnalysisEngineResult& r) { return r.engine == w.engine; });

            if (it == results.end() || !it->success) continue;

            // Score this engine's findings
            double engine_score = score_findings(it->findings);
            total_score += engine_score * w.weight * w.reliability;
            total_weight += w.weight;
        }

        if (total_weight == 0) return 0;

        // Normalize to 0-100
        int raw_score = static_cast<int>((total_score / total_weight) * 100);
        return std::clamp(raw_score, 0, 100);
    }

    double score_findings(const std::vector<Finding>& findings) {
        double score = 0.0;
        for (auto& f : findings) {
            score += severity_score(f.severity);
        }
        // Normalize: diminishing returns for many findings
        return 1.0 - std::exp(-score / 10.0);  // approaches 1.0 asymptotically
    }

    double severity_score(const std::string& severity) {
        if (severity == "critical") return 5.0;
        if (severity == "high")     return 3.0;
        if (severity == "medium")   return 1.5;
        if (severity == "low")      return 0.5;
        return 0.1;  // info
    }
};

// VMProtectEnd();
```

## Heuristic Decision Tree

```cpp
// VMProtectBeginUltra("heuristics");

struct HeuristicRule {
    std::string name;
    int score_adjustment;  // positive = more malicious
    std::function<bool(const std::vector<Finding>&, const nlohmann::json&)> condition;
};

static const std::vector<HeuristicRule> kHeuristicRules = {
    // Process injection + network = likely RAT/trojan
    {"injection_plus_network", 25,
     [](const auto& findings, const auto& meta) {
         bool has_injection = false, has_network = false;
         for (auto& f : findings) {
             if (f.title.find("Injection") != std::string::npos) has_injection = true;
             if (f.title.find("Network") != std::string::npos) has_network = true;
         }
         return has_injection && has_network;
     }},

    // High entropy + no ASLR + process injection = packed dropper
    {"packed_dropper", 30,
     [](const auto& findings, const auto& meta) {
         bool packed = false, no_aslr = false, injection = false;
         for (auto& f : findings) {
             if (f.title.find("packed") != std::string::npos ||
                 f.title.find("entropy") != std::string::npos) packed = true;
             if (f.title == "No ASLR") no_aslr = true;
             if (f.title.find("Injection") != std::string::npos) injection = true;
         }
         return packed && no_aslr && injection;
     }},

    // File encryption APIs = ransomware
    {"ransomware_indicator", 40,
     [](const auto& findings, const auto& meta) {
         for (auto& f : findings) {
             if (f.title == "File Encryption Capability") return true;
         }
         return false;
     }},

    // Known malicious hash (enrichment)
    {"known_malicious", 50,
     [](const auto& findings, const auto& meta) {
         for (auto& f : findings) {
             if (f.engine == "enrichment" &&
                 f.metadata.contains("detection_ratio")) {
                 int malicious = f.metadata["detection_ratio"]["malicious"].get<int>();
                 if (malicious >= 5) return true;
             }
         }
         return false;
     }},

    // Clean on VirusTotal = reduce score
    {"vt_clean", -20,
     [](const auto& findings, const auto& meta) {
         for (auto& f : findings) {
             if (f.engine == "enrichment" &&
                 f.metadata.contains("detection_ratio")) {
                 int malicious = f.metadata["detection_ratio"]["malicious"].get<int>();
                 int total = f.metadata["detection_ratio"]["total"].get<int>();
                 if (total > 30 && malicious == 0) return true;
             }
         }
         return false;
     }},
};

// VMProtectEnd();
```

## MITRE ATT&CK Mapping

```cpp
struct MitreMapping {
    std::string technique_id;
    std::string technique_name;
    std::string tactic;
    std::vector<std::string> finding_keywords;
};

static const std::vector<MitreMapping> kMitreMappings = {
    {"T1055",   "Process Injection",          "defense-evasion",
     {"Process Injection", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}},

    {"T1003",   "OS Credential Dumping",      "credential-access",
     {"Credential", "lsass", "MiniDumpWriteDump", "CryptUnprotectData"}},

    {"T1547.001", "Boot or Logon Autostart",  "persistence",
     {"Registry Persistence", "RegSetValueEx", "Run key"}},

    {"T1543.003", "Windows Service",          "persistence",
     {"Service Creation", "CreateService"}},

    {"T1486",   "Data Encrypted for Impact",  "impact",
     {"File Encryption", "ransomware", "CryptEncrypt", "BCryptEncrypt"}},

    {"T1071",   "Application Layer Protocol", "command-and-control",
     {"Network Communication", "HTTP", "InternetOpen", "URLDownload"}},

    {"T1059",   "Command and Scripting",      "execution",
     {"Script", "PowerShell", "VBScript", "JavaScript", "WScript.Shell"}},

    {"T1497",   "Virtualization/Sandbox Evasion", "defense-evasion",
     {"Anti-Analysis", "IsDebuggerPresent", "CPUID", "RDTSC"}},

    {"T1027",   "Obfuscated Files",           "defense-evasion",
     {"packed", "High entropy", "encrypted section", "obfuscated"}},

    {"T1110",   "Brute Force",                "credential-access",
     {"Brute Force", "failed auth"}},

    {"T1021",   "Remote Services",            "lateral-movement",
     {"Lateral Movement", "RDP", "SMB", "WinRM"}},

    {"T1056.001", "Keylogging",               "collection",
     {"Keylogging", "SetWindowsHookEx", "GetAsyncKeyState"}},

    {"T1113",   "Screen Capture",             "collection",
     {"Screen Capture", "BitBlt", "GetDC"}},

    {"T1041",   "Exfiltration Over C2",       "exfiltration",
     {"exfiltration", "C2", "beacon"}},
};

std::vector<std::string> map_mitre(const std::vector<Finding>& findings) {
    std::set<std::string> techniques;

    for (auto& mapping : kMitreMappings) {
        for (auto& finding : findings) {
            // Check finding metadata for explicit MITRE mapping
            if (finding.metadata.contains("mitre")) {
                techniques.insert(finding.metadata["mitre"].get<std::string>());
                continue;
            }

            // Keyword matching
            for (auto& keyword : mapping.finding_keywords) {
                if (finding.title.find(keyword) != std::string::npos ||
                    finding.description.find(keyword) != std::string::npos) {
                    techniques.insert(mapping.technique_id);
                    break;
                }
            }
        }
    }

    return std::vector<std::string>(techniques.begin(), techniques.end());
}
```

## Verdict Classification

```cpp
std::pair<Verdict, double> classify(int score, const std::vector<Finding>& findings) {
    int critical_count = 0, high_count = 0;
    for (auto& f : findings) {
        if (f.severity == "critical") critical_count++;
        if (f.severity == "high") high_count++;
    }

    // Hard thresholds
    if (score >= 80 || critical_count >= 3) {
        return {Verdict::kMalicious, std::min(1.0, score / 100.0 + 0.1)};
    }
    if (score >= 50 || (critical_count >= 1 && high_count >= 2)) {
        return {Verdict::kSuspicious, score / 100.0};
    }
    if (score >= 20) {
        return {Verdict::kSuspicious, score / 200.0};
    }
    if (score > 0) {
        return {Verdict::kClean, 1.0 - (score / 100.0)};
    }
    return {Verdict::kUnknown, 0.0};
}

std::string score_to_risk(int score) {
    if (score >= 80) return "critical";
    if (score >= 60) return "high";
    if (score >= 40) return "medium";
    if (score >= 20) return "low";
    return "none";
}
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Not normalizing engine scores before aggregation | Each engine has different output ranges — normalize to 0-1 |
| Scoring engines that didn't run | Check `success` flag — don't penalize for missing engines |
| Linear score accumulation | Use diminishing returns (exp decay) — 100 medium findings ≠ 100x score |
| Missing VMProtect markers | Scoring algorithm is core IP — must be virtualized |
| Hardcoded MITRE mappings without metadata | Prefer explicit `mitre` field in finding metadata, fallback to keyword |
| Not handling conflicting verdicts | When engines disagree, weight by reliability score |
| Scoring phantom events (V1 bug) | Only score findings that actually have data backing them |
