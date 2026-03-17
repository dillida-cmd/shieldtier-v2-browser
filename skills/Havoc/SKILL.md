---
name: Havoc
description: Use when building the behavioral sandbox and advanced analysis engines — inline sandbox, behavioral signatures, PE capability detection, script detonation, shellcode emulation, heap forensics, DNS/network forensics, WASM inspector, INetSim signatures, ArtifactQL
---

# S5 — Havoc: Behavioral Sandbox & Advanced Analysis

## Overview

Port V1's inline behavioral sandbox and all advanced analysis subsystems to C++. The sandbox executes suspicious code patterns and monitors behavior. Advanced analyzers inspect PE API sequences, scripts, shellcode, heap structures, DNS/network patterns, WASM binaries, and INetSim artifacts.

## Dependencies

- **Requires:** S0 (foundation), S1 (cef-shell for CDP access where needed)
- **Blocks:** S10 (scoring engine consumes sandbox + advanced findings)

## File Ownership

```
src/native/analysis/sandbox/
  engine.cpp/.h            (behavioral sandbox orchestrator)
  signatures.cpp/.h        (behavioral signature matching — VMProtect marker)
  network_profiler.cpp/.h  (network behavior profiling)
  script_analyzer.cpp/.h   (inline script analysis)
  collector.cpp/.h         (event collection and aggregation)

src/native/analysis/advanced/
  pe_capability/
    analyzer.cpp/.h        (PE API sequence detection, capability mapping)
    api_database.cpp/.h    (known malicious API combination database)
  script_detonation/
    engine.cpp/.h          (script execution sandbox)
    js_analyzer.cpp/.h     (JavaScript deobfuscation + analysis)
    vbs_analyzer.cpp/.h    (VBScript analysis)
    ps_analyzer.cpp/.h     (PowerShell analysis)
  shellcode_emulator/
    emulator.cpp/.h        (x86/x64 shellcode emulation)
    syscall_hooks.cpp/.h   (emulated Windows API hooks)
  heap_forensics/
    analyzer.cpp/.h        (heap spray detection, UAF patterns)
  dns_network/
    analyzer.cpp/.h        (DNS/network forensics)
    dga_detector.cpp/.h    (domain generation algorithm detection)
  wasm_inspector/
    inspector.cpp/.h       (WASM binary analysis via wabt)
  inetsim/
    signature_matcher.cpp/.h (match INetSim captured traffic against known patterns)
  artifactql/
    engine.cpp/.h          (artifact query engine for cross-referencing findings)
```

## Exit Criteria

Feed sample buffer → behavioral sandbox produces event stream + findings. PE capability analyzer detects API-based capabilities. Script detonation extracts IOCs from JS/VBS/PS1. Shellcode emulator traces API calls. All return `AnalysisEngineResult`.

---

## Behavioral Sandbox Engine

```cpp
class SandboxEngine {
public:
    AnalysisEngineResult analyze(const FileBuffer& file) {
        AnalysisEngineResult result;
        result.engine = AnalysisEngine::kSandbox;

        // Collect behavioral events from file content analysis
        auto events = collector_.collect(file);

        // Match against behavioral signatures
        auto sig_findings = signature_matcher_.match(events);
        result.findings.insert(result.findings.end(),
            sig_findings.begin(), sig_findings.end());

        // Profile network behavior from extracted indicators
        auto net_findings = network_profiler_.profile(file);
        result.findings.insert(result.findings.end(),
            net_findings.begin(), net_findings.end());

        // Analyze embedded scripts
        auto script_findings = script_analyzer_.analyze(file);
        result.findings.insert(result.findings.end(),
            script_findings.begin(), script_findings.end());

        result.success = true;
        return result;
    }

private:
    EventCollector collector_;
    SignatureMatcher signature_matcher_;
    NetworkProfiler network_profiler_;
    ScriptAnalyzer script_analyzer_;
};
```

## Behavioral Signatures (VMProtect-marked)

```cpp
// signatures.cpp — VMProtect virtualizes this function
// VMProtectBeginUltra("sig_match");

struct BehavioralSignature {
    std::string name;
    std::string severity;
    std::string mitre_technique;
    std::function<bool(const std::vector<BehaviorEvent>&)> matcher;
};

// Example signatures:
static const std::vector<BehavioralSignature> kSignatures = {
    {
        "Process Injection Chain",
        "critical",
        "T1055",
        [](const std::vector<BehaviorEvent>& events) {
            bool has_alloc = false, has_write = false, has_thread = false;
            for (auto& e : events) {
                if (e.api == "VirtualAllocEx") has_alloc = true;
                if (e.api == "WriteProcessMemory") has_write = true;
                if (e.api == "CreateRemoteThread") has_thread = true;
            }
            return has_alloc && has_write && has_thread;
        }
    },
    {
        "Credential Dumping",
        "critical",
        "T1003",
        [](const std::vector<BehaviorEvent>& events) {
            for (auto& e : events) {
                if (e.api == "OpenProcess" && e.args.contains("lsass")) return true;
                if (e.api == "MiniDumpWriteDump") return true;
            }
            return false;
        }
    },
    // ... more signatures ...
};

// VMProtectEnd();
```

## PE Capability Analyzer

```cpp
struct Capability {
    std::string name;
    std::string description;
    std::string severity;
    std::string mitre_id;
    std::vector<std::string> required_apis;
    int min_match;  // minimum APIs from required_apis that must be present
};

static const std::vector<Capability> kCapabilities = {
    {"Process Injection", "Can inject code into other processes", "critical", "T1055",
     {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx"}, 2},

    {"Keylogging", "Can capture keystrokes", "high", "T1056.001",
     {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"}, 1},

    {"Screen Capture", "Can capture screenshots", "medium", "T1113",
     {"BitBlt", "GetDC", "CreateCompatibleDC", "GetDesktopWindow"}, 3},

    {"Registry Persistence", "Can modify registry for persistence", "high", "T1547.001",
     {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA"}, 1},

    {"Service Creation", "Can create Windows services", "high", "T1543.003",
     {"CreateServiceA", "CreateServiceW", "StartServiceA"}, 1},

    {"Network Communication", "Can communicate over network", "medium", "T1071",
     {"InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
      "WSAStartup", "connect", "send", "recv"}, 2},

    {"File Encryption", "Can encrypt files (ransomware indicator)", "critical", "T1486",
     {"CryptEncrypt", "CryptGenKey", "CryptImportKey", "BCryptEncrypt"}, 2},

    {"Anti-Analysis", "Contains anti-analysis techniques", "high", "T1497",
     {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
      "GetTickCount", "QueryPerformanceCounter"}, 2},
};

std::vector<Finding> detect_capabilities(const nlohmann::json& imports) {
    std::vector<Finding> findings;
    std::set<std::string> import_set;
    for (auto& imp : imports) {
        import_set.insert(imp["function"].get<std::string>());
    }

    for (auto& cap : kCapabilities) {
        int matches = 0;
        std::vector<std::string> matched_apis;
        for (auto& api : cap.required_apis) {
            if (import_set.count(api)) {
                matches++;
                matched_apis.push_back(api);
            }
        }
        if (matches >= cap.min_match) {
            findings.push_back({
                cap.name, cap.description, cap.severity, "advanced",
                {{"mitre", cap.mitre_id}, {"matched_apis", matched_apis}}
            });
        }
    }
    return findings;
}
```

## Shellcode Emulator

```cpp
// Lightweight x86/x64 emulator for shellcode analysis
// Hooks common Windows APIs to trace behavior without executing on host

struct EmulatedCall {
    std::string api;
    nlohmann::json args;
    uint64_t address;
};

class ShellcodeEmulator {
public:
    struct EmulationResult {
        std::vector<EmulatedCall> api_calls;
        std::vector<std::string> extracted_urls;
        std::vector<std::string> extracted_strings;
        std::vector<Finding> findings;
        bool completed = false;
        std::string error;
    };

    EmulationResult emulate(const uint8_t* shellcode, size_t size,
                            int max_instructions = 100000) {
        EmulationResult result;

        // Initialize emulated memory space
        // Map shellcode at base address
        // Set up stack, PEB/TEB structures
        // Hook API stubs at known addresses

        // Emulation loop (simplified):
        // for each instruction:
        //   decode instruction
        //   if call to hooked API: record call, return fake success
        //   if memory access out of bounds: stop
        //   if max_instructions reached: stop
        //   execute instruction on emulated state

        // Extract IOCs from API calls
        for (auto& call : result.api_calls) {
            if (call.api == "URLDownloadToFileA" || call.api == "InternetOpenUrlA") {
                if (call.args.contains("url")) {
                    result.extracted_urls.push_back(call.args["url"]);
                }
            }
        }

        return result;
    }
};
```

## DGA Detector (DNS/Network)

```cpp
// Detect Domain Generation Algorithms by analyzing domain entropy and patterns

struct DGAResult {
    bool is_dga;
    double confidence;
    std::string algorithm_hint;
};

DGAResult detect_dga(const std::string& domain) {
    // Extract second-level domain
    auto sld = extract_sld(domain);
    if (sld.empty()) return {false, 0.0, ""};

    double entropy = string_entropy(sld);
    double consonant_ratio = count_consonants(sld) / static_cast<double>(sld.size());
    int bigram_score = unusual_bigram_count(sld);
    bool has_digits = std::any_of(sld.begin(), sld.end(), ::isdigit);
    int length = sld.size();

    // Heuristic scoring
    double score = 0.0;
    if (entropy > 3.5) score += 0.3;
    if (consonant_ratio > 0.7) score += 0.2;
    if (bigram_score > 3) score += 0.2;
    if (has_digits && length > 8) score += 0.15;
    if (length > 15) score += 0.15;

    return {score > 0.5, score, score > 0.7 ? "high_entropy_random" : "mixed"};
}
```

## WASM Inspector (wabt)

```cpp
#include <wabt/binary-reader.h>
#include <wabt/ir.h>

struct WasmAnalysis {
    int function_count = 0;
    int import_count = 0;
    int export_count = 0;
    std::vector<std::string> imported_functions;
    std::vector<std::string> exported_functions;
    std::vector<Finding> findings;
};

WasmAnalysis analyze_wasm(const FileBuffer& file) {
    WasmAnalysis result;

    wabt::ReadBinaryOptions options;
    wabt::Errors errors;
    wabt::Module module;

    auto wasm_result = wabt::ReadBinaryIr(
        file.filename.c_str(), file.data.data(), file.size(),
        options, &errors, &module);

    if (!wasm_result) {
        result.findings.push_back({"Invalid WASM", "Failed to parse WebAssembly binary",
                                    "info", "advanced", {}});
        return result;
    }

    result.function_count = module.funcs.size();
    result.import_count = module.imports.size();
    result.export_count = module.exports.size();

    for (auto& imp : module.imports) {
        result.imported_functions.push_back(
            imp->module_name + "." + imp->field_name);
    }

    for (auto& exp : module.exports) {
        result.exported_functions.push_back(exp->name);
    }

    // Check for suspicious patterns
    if (result.import_count == 0 && result.function_count > 50) {
        result.findings.push_back({
            "Self-Contained WASM",
            "Large WASM module with no imports — may be obfuscated or packed",
            "medium", "advanced", {}
        });
    }

    return result;
}
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Shellcode emulator executing on host | Must be pure emulation — never execute sample bytes natively |
| DGA detector false positives on CDN domains | Whitelist known CDN patterns (akamai, cloudfront, etc.) |
| Archive bomb in script detonation | Limit deobfuscation depth and output size |
| Not setting VMProtect markers on signature matching | Signatures are competitive IP — mark for virtualization |
| Unbounded API call tracing | Cap emulation at max_instructions to prevent infinite loops |
| Missing MITRE ATT&CK mappings | Every capability and signature needs a technique ID |
