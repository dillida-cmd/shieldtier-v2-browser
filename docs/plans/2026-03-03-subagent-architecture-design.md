# ShieldTier V2 — Sub-Agent Architecture Design

**Date:** 2026-03-03
**Status:** Approved
**Approach:** Domain-Parallel Streams (Approach B)

---

## Executive Summary

ShieldTier V2 requires **14 skilled sub-agents** organized into **7 skill domains**, dispatched across **5 waves**. This architecture supports both Claude Code worktree-isolated execution (~35 days) and human team execution (6 engineers, ~18 weeks).

The decomposition follows domain-parallel streams: independent skill domains run concurrently, synchronized at dependency gates. This reduces wall-clock time from ~43 weeks (sequential) to ~18 weeks (parallel) for human teams, or ~35 days for Claude Code agents.

---

## Approaches Evaluated

### Approach A: Phase-Sequential (Rejected)
Follow PLAN.md phases A→I linearly. Simple dependencies but zero parallelism — 43 weeks wall-clock.

### Approach B: Domain-Parallel Streams (Selected)
Decompose by skill domain. 6+ agents work simultaneously. Synchronized at dependency gates. Reduces to ~18 weeks (human) / ~35 days (Claude Code).

### Approach C: Micro-Agent Swarm (Rejected)
40+ tiny agents each owning single files. Maximum theoretical parallelism but coordination cost exceeds benefit — shared headers, IPC protocol, and error patterns need consistency across all agents.

---

## Agent Roster (14 Agents)

| # | Codename | Agent ID | Skill Domain | File Ownership | Human Role |
|---|----------|----------|-------------|---------------|-----------|
| S0 | **Axiom** | `foundation` | Build Systems | `CMakeLists.txt`, `cmake/*`, `scripts/*`, `third_party/` | Build Engineer |
| S1 | **Chrono** | `cef-shell` | CEF/Chromium | `src/native/app/*`, `src/native/browser/*` | Browser Platform Engineer |
| S2 | **Nexus** | `ipc-bridge` | CEF + React | `src/native/ipc/*`, renderer CEF bootstrap | Full-Stack Bridge Engineer |
| S3 | **Rune** | `yara-engine` | Malware Analysis | `src/native/analysis/yara/*` | Threat Detection Engineer |
| S4 | **Scalpel** | `file-analysis` | Binary Analysis | `src/native/analysis/fileanalysis/*` | Reverse Engineer |
| S5 | **Havoc** | `sandbox-advanced` | Behavioral Analysis | `src/native/analysis/sandbox/*`, `src/native/analysis/advanced/*` | Sandbox Engineer |
| S6 | **Oracle** | `enrichment-email-content` | Network + Parsing | `src/native/analysis/enrichment/*`, `email/*`, `content/*` | Threat Intel Engineer |
| S7 | **Sentry** | `log-threatfeed-capture` | Data Processing | `src/native/analysis/loganalysis/*`, `threatfeed/*`, `capture/*` | Data Engineer |
| S8 | **Phantom** | `vm-sandbox` | Virtualization | `src/native/vm/*`, `agents/vm-agent/*` | VM/Hypervisor Engineer |
| S9 | **Vault** | `chat-auth-config-export` | Infrastructure | `src/native/chat/*`, `auth/*`, `config/*`, `export/*`, `network/*` | Backend Engineer |
| S10 | **Verdict** | `scoring-engine` | ML/Detection | `src/native/scoring/*` | Detection Engineer |
| S11 | **Aegis** | `security-protection` | Anti-Tamper | `src/native/security/*` | Security Engineer |
| S12 | **Nimbus** | `cloud-backend` | Server-Side | License server, rule API, `/analyze` endpoint | Cloud Engineer |
| S13 | **Obsidian** | `build-harden-package` | Release Engineering | LLVM obfuscation, VMProtect, signing, packaging | Release Engineer |

---

## Dependency Graph

```
        S0 Axiom (foundation)
        |
        S1 Chrono (cef-shell)
       /|\
      / | \
 S2 Nexus | S7 Sentry
    |   |   |
    |   +-- S3 Rune (yara) --------+
    |   +-- S4 Scalpel (file) -----+
    |   +-- S5 Havoc (sandbox) ----+
    |   +-- S6 Oracle (enrich)     |
    |   +-- S8 Phantom (vm)        |
    |   +-- S9 Vault (infra)       |
    |                               |
    |                 S10 Verdict (scoring)
    |                               |
    |                 S11 Aegis (security)
    |                               |
    |                 S12 Nimbus (cloud)
    |                               |
    +---------------- S13 Obsidian (harden+package)
```

### Dependency Rules

- S0 Axiom blocks ALL agents (build system must exist)
- S1 Chrono blocks S2 Nexus (IPC needs CEF shell) and S7 Sentry (capture uses CEF CDP)
- S3 Rune, S4 Scalpel, S5 Havoc block S10 Verdict (scoring consumes their output interfaces)
- S10 Verdict blocks S11 Aegis (security protects scoring functions)
- S10 Verdict, S11 Aegis block S12 Nimbus (cloud serves scoring + validates licenses)
- ALL block S13 Obsidian (hardening is the final overlay)
- S3 Rune, S4 Scalpel, S5 Havoc, S6 Oracle, S8 Phantom, S9 Vault have NO inter-dependencies (fully parallel)

---

## Dispatch Waves

### Wave 0: Foundation (Sequential)

**Agent:** S0 Axiom `foundation`
**Duration:** 3 days (Claude) / 1 week (human)
**Parallelism:** 1

Deliverables:
- `CMakeLists.txt` — top-level CMake with CEF SDK, Ninja generator
- `cmake/FindCEF.cmake` — CEF binary distribution discovery
- `cmake/ObfuscationPasses.cmake` — stub for LLVM flags
- `cmake/VMProtect.cmake` — stub for post-link step
- `scripts/download-cef.sh` — platform-specific CEF SDK fetch
- `third_party/` — FetchContent for libyara, libsodium, libcurl, pe-parse, libarchive, wabt
- `src/native/common/types.h` — shared types (AnalysisResult, ThreatVerdict, FileBuffer)
- `src/native/common/result.h` — Result<T, E> error handling
- `src/native/common/json.h` — JSON serialization (nlohmann/json or rapidjson)
- `.clang-format` — snake_case enforcement

Exit criteria: `cmake -G Ninja .. && ninja` compiles empty CEF app that opens a window.

### Wave 1: Browser Core (Sequential)

**Agent:** S1 Chrono `cef-shell`
**Duration:** 5 days (Claude) / 2 weeks (human)
**Parallelism:** 1

Deliverables:
- `src/native/app/main.cpp` — CEF initialization, message loop
- `src/native/app/app_handler.cpp` — CefClient implementation
- `src/native/app/browser_handler.cpp` — CefBrowserProcessHandler
- `src/native/browser/session_manager.cpp` — per-tab CefBrowser + CefRequestContext
- `src/native/browser/response_filter.cpp` — CefResponseFilter streaming interception
- `src/native/browser/download_handler.cpp` — CefDownloadHandler lifecycle
- `src/native/browser/request_handler.cpp` — CefRequestHandler network policy
- `src/native/browser/cookie_manager.cpp` — per-session CefCookieManager
- `src/native/browser/navigation.cpp` — back/forward/reload/URL bar

Exit criteria: Browser opens, navigates, intercepts downloads in-memory, blocks private IPs.

### Wave 2: Parallel Domain Streams (Maximum Concurrency)

**Agents:** S2 Nexus, S3 Rune, S4 Scalpel, S5 Havoc, S6 Oracle, S7 Sentry, S8 Phantom, S9 Vault, S10 Verdict
**Duration:** 10 days (Claude) / 8 weeks (human) — gated by S8 Phantom
**Parallelism:** 9 concurrent agents

#### S2 Nexus: `ipc-bridge` (4 days Claude / 1 week human)
- `src/native/ipc/handler.cpp` — CefMessageRouterBrowserSideHandler
- `src/native/ipc/protocol.h` — JSON message schema (all IPC types)
- Renderer-side: `window.cefQuery()` wrapper, typed message dispatch
- Vite build config → `dist/renderer/`
- CEF loads `dist/renderer/index.html`

Exit criteria: React UI sends IPC request → native responds → UI renders result.

#### S3 Rune: `yara-engine` (4 days Claude / 1.5 weeks human)
- `src/native/analysis/yara/scanner.cpp` — libyara yr_rules_scan_mem()
- `yara/rule_manager.cpp` — load/compile rules, encrypted rule decryption hook
- `yara/builtin_rules.cpp` — open-source rules compiled in

Exit criteria: Scan PE buffer with 24 YARA rules, return matches as JSON.

#### S4 Scalpel: `file-analysis` (5 days Claude / 2 weeks human)
- `src/native/analysis/fileanalysis/manager.cpp` — analysis orchestrator
- `pe_analyzer.cpp` — pe-parse (imports, sections, entropy, capabilities)
- `pdf_analyzer.cpp` — PDF stream extraction, JS detection
- `office_analyzer.cpp` — OLE/OOXML macro extraction
- `archive_analyzer.cpp` — libarchive recursive extraction
- `general_analyzer.cpp` — entropy, strings, magic bytes

Exit criteria: Feed PE/PDF/Office/ZIP buffer → structured analysis JSON.

#### S5 Havoc: `sandbox-advanced` (8 days Claude / 3 weeks human)
- `src/native/analysis/sandbox/` — engine, signatures, network_profiler, script_analyzer, collector
- `src/native/analysis/advanced/pe_capability/` — PE API sequence detection
- `advanced/script_detonation/` — script execution sandbox
- `advanced/shellcode_emulator/` — x86 emulation
- `advanced/heap_forensics/` — heap analysis
- `advanced/dns_network/` — DNS/network forensics
- `advanced/wasm_inspector/` — wabt integration
- `advanced/inetsim/` — fake service signatures
- `advanced/artifactql/` — artifact query engine

Exit criteria: Behavioral sandbox on sample buffer → event stream + findings.

#### S6 Oracle: `enrichment-email-content` (5 days Claude / 2 weeks human)
- `src/native/analysis/enrichment/` — manager, extractors, providers (VT, AbuseIPDB, OTX, URLhaus, WHOIS, MISP)
- `src/native/analysis/email/` — manager, MIME parser, header analyzer, content analyzer
- `src/native/analysis/content/*` — page content analysis

Exit criteria: Hash → VT + AbuseIPDB query → merged results. EML → parsed + analyzed.

#### S7 Sentry: `log-threatfeed-capture` (8 days Claude / 3 weeks human)
- `src/native/analysis/loganalysis/` — manager, detector, normalizer, 13 converters, 6 engines
- `src/native/analysis/threatfeed/*` — STIX/TAXII ingestion
- `src/native/capture/` — manager, har_builder, session (CEF CDP)

Exit criteria: EVTX → normalize → detect. HAR capture from CEF session.

#### S8 Phantom: `vm-sandbox` (15 days Claude / 8 weeks human) — LONGEST AGENT
- `src/native/vm/` — full VM lifecycle (manager, orchestrator, qemu_args, installer, image_builder, agent_builder, agent_provisioner, serial_console, scoring, protocol, types)
- `vm/inetsim_server.cpp` — DNS/HTTP/HTTPS/SMTP/FTP/DoH simulation
- `vm/hypervisor_hvf.cpp` — macOS Hypervisor.framework
- `vm/hypervisor_kvm.cpp` — Linux KVM ioctl
- `vm/hypervisor_whpx.cpp` — Windows WHPX
- `vm/vmi_engine.cpp` — EPT-based agentless VMI
- `vm/anti_evasion.cpp` — CPUID masking, TSC offset, environment realism, human simulation
- `agents/vm-agent/` — improved Go agent (real ETW, proc_connector)

Exit criteria: Boot VM, inject sample, agentless monitoring (Linux), improved agent (Windows), INetSim DNS+HTTP+SMTP.

#### S9 Vault: `chat-auth-config-export` (5 days Claude / 1.5 weeks human)
- `src/native/chat/` — manager, shieldcrypt (libsodium), network (WebSocket), message_store
- `src/native/auth/` — manager, types (JWT, bcrypt)
- `src/native/config/store.cpp` — atomic JSON config, encrypted
- `src/native/export/` — manager, html_template, json_export, zip_builder, defang
- `src/native/network/policy.cpp` — network policy

Exit criteria: Encrypted config, HTML/JSON/ZIP reports, E2E encrypted chat.

#### S10 Verdict: `scoring-engine` (5 days Claude / 2 weeks human)
- `src/native/scoring/engine.cpp` — consolidated scoring (VMProtect marker)
- `scoring/heuristics.cpp` — detection heuristics (VMProtect marker)
- `scoring/threat_model.cpp` — threat classification, MITRE ATT&CK mapping

Depends on: S3 Rune, S4 Scalpel, S5 Havoc interfaces (starts parallel, finalizes after they deliver).
Exit criteria: Analysis results from all engines → unified threat score + verdict.

### Wave 3: Protection + Cloud (After Wave 2 Core)

**Agents:** S11 Aegis, S12 Nimbus
**Duration:** 10 days (Claude) / 4 weeks (human)
**Parallelism:** 2 concurrent

#### S11 Aegis: `security-protection` (10 days Claude / 4 weeks human)
- `src/native/security/license.cpp` — license validation + tier gating (VMProtect marker)
- `security/fingerprint.cpp` — 5-factor machine fingerprint (cross-platform)
- `security/attestation.cpp` — code self-hashing
- `security/integrity_mesh.cpp` — guard A/B/C cross-validation
- `security/anti_debug.cpp` — 12 detection methods (ptrace, sysctl, mach_absolute_time, DR0-DR3, INT3 scan, parent check, PEB, NtQuery, NtGlobalFlag, TLS callbacks, fork watchdog, timing)
- `security/encrypted_pages.cpp` — lazy decryption via SIGSEGV/VEH (Linux/Windows; limited on macOS Hardened Runtime)
- `security/rule_crypto.cpp` — AES-256-GCM + Ed25519 verification
- `security/keychain.cpp` — Secure Enclave (macOS), DPAPI (Windows), Secret Service (Linux)
- Silent corruption response (corrupt crypto keys, inject subtle errors, delayed failure)

Exit criteria: License validates against fingerprint, integrity mesh detects patching, anti-debug silently corrupts on debugger.

#### S12 Nimbus: `cloud-backend` (10 days Claude / 3 weeks human)
- License server: `/auth/activate`, `/auth/validate`, `/license/heartbeat`, `/license/revoke`
- Rule packaging: compile YARA → AES-256-GCM encrypt → Ed25519 sign → serve
- `/analyze` API: feature vectors → proprietary YARA + ML scoring → verdict
- Tier gating middleware (free/pro/team/enterprise)
- Bloom filter generation (100M+ known-bad hashes, ~50MB)

Exit criteria: Activate license → signed blob → encrypted rules → feature vector → verdict.

### Wave 4: Hardening + Release (After Everything)

**Agent:** S13 Obsidian `build-harden-package`
**Duration:** 7 days (Claude) / 3 weeks (human)
**Parallelism:** 1

Deliverables:
- LLVM obfuscation: Polaris-Obfuscator or Hikari fork in CMake (CFF + MBA + BCF + string encryption + instruction substitution)
- VMProtect post-link: `scripts/vmprotect-post-link.sh` — virtualize marked functions
- Code signing: Apple notarization (notarytool), Windows Authenticode (EV cert), Linux GPG
- Packaging: macOS .app→DMG (universal arm64+x64), Windows NSIS, Linux AppImage
- Renderer protection: javascript-obfuscator in Vite (CFF, rc4 string encryption, self-defending, anti-DevTools)
- Integrity hash embedding: SHA-256 of code sections in read-only data segment

Exit criteria: Obfuscated + VMProtect'd + signed + notarized binary for all platforms.

---

## Shared Interfaces (Merge Boundaries)

| Interface | Owner | Consumers | Contract |
|-----------|-------|-----------|----------|
| `src/native/common/types.h` | S0 Axiom | ALL | AnalysisResult, ThreatVerdict, FileBuffer, shared enums |
| `src/native/ipc/protocol.h` | S2 Nexus | S1 Chrono, all analysis agents | JSON IPC message schema |
| Analysis output format | S10 Verdict | S3 Rune, S4 Scalpel, S5 Havoc, S6 Oracle, S7 Sentry | Each engine → AnalysisEngineResult → S10 Verdict consumes |
| Rule crypto interface | S11 Aegis | S3 Rune | decrypt_rules(blob) → compiled_rules |
| License tier check | S11 Aegis | S10 Verdict, S12 Nimbus | get_license_tier() → tier enum |
| VMProtect markers | S13 Obsidian | S10 Verdict, S11 Aegis, S3 Rune | VMProtectBeginUltra() / VMProtectEnd() wrappers |

---

## Timeline Summary

### Claude Code Execution

| Wave | Agents | Parallel | Duration | Cumulative |
|------|--------|----------|----------|-----------|
| 0 | S0 Axiom | 1 | 3d | 3d |
| 1 | S1 Chrono | 1 | 5d | 8d |
| 2 | S2-S10 (Nexus...Verdict) | 9 | 15d | 23d |
| 3 | S11 Aegis, S12 Nimbus | 2 | 10d | 33d |
| 4 | S13 Obsidian | 1 | 7d | 40d |
| **Total** | **14 agents** | | | **~40 days** |

### Human Team Execution (6 Engineers)

| Role | Agents | Duration |
|------|--------|----------|
| Browser Platform Engineer | S0 Axiom, S1 Chrono, S2 Nexus | Weeks 1-5 |
| Threat Detection Engineer | S3 Rune, S4 Scalpel, S10 Verdict | Weeks 3-12 |
| Sandbox Engineer | S5 Havoc, S8 Phantom | Weeks 3-14 |
| Threat Intel Engineer | S6 Oracle, S7 Sentry | Weeks 3-10 |
| Security Engineer | S9 Vault, S11 Aegis, S13 Obsidian | Weeks 3-22 |
| Cloud Engineer | S12 Nimbus | Weeks 15-18 |
| **Total** | **6 engineers** | **~22 weeks** |

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| S8 Phantom (vm-sandbox) is critical path at 8 weeks | Split into sub-phases: VM-core (2w) → hypervisor (3w) → VMI (3w). Ship VM-core first |
| Shared interface drift between agents | S0 Axiom creates interface stubs upfront. Review gate before Wave 3 |
| macOS Hardened Runtime blocks encrypted pages | S11 Aegis uses alternative approach on macOS (encrypt/decrypt in userspace, no SIGSEGV) |
| VMProtect license cost | Budget for Company License. Evaluate Themida as fallback |
| LLVM obfuscation breaks correct output | S13 Obsidian runs full test suite after obfuscation. Performance benchmark: <2x overhead |
| CEF SDK version compatibility | Pin to specific CEF build. S0 Axiom documents exact version in cmake/FindCEF.cmake |

---

## Claude Code Dispatch Commands

Each wave dispatches agents using worktree isolation:

```
Wave 0: 1 agent  (sequential)
Wave 1: 1 agent  (sequential)
Wave 2: 9 agents (parallel, isolation: worktree)
Wave 3: 2 agents (parallel, isolation: worktree)
Wave 4: 1 agent  (sequential)
```

Total dispatches: 14 agents across 5 waves.
Maximum concurrent: 9 (Wave 2).
