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

## References

- [CEF Project](https://bitbucket.org/chromiumembedded/cef)
- [CEF C++ API Docs](https://magpcss.org/ceforum/apidocs3/)
- [CEF Binary Distributions](https://cef-builds.spotifycdn.com/index.html)
- [Chrome DevTools Protocol — Fetch Domain](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/)
- [Electron Debugger API](https://www.electronjs.org/docs/latest/api/debugger)
- [Electron Issue #23594](https://github.com/electron/electron/issues/23594) — Fetch.getResponseBody
- [Electron Issue #27768](https://github.com/electron/electron/issues/27768) — CDP Fetch crashes
- [Electron Issue #37491](https://github.com/electron/electron/issues/37491) — Response body retrieval
- [Electron Issue #36261](https://github.com/electron/electron/issues/36261) — WebRequest body access
- [Electron Issue #46048](https://github.com/electron/electron/issues/46048) — CDP event dispatching
- [Playwright Issue #6573](https://github.com/microsoft/playwright/issues/6573) — Downloads canceled
- [Playwright crNetworkManager.ts](https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/chromium/crNetworkManager.ts)
- [mockttp](https://github.com/httptoolkit/mockttp) — Node.js MITM proxy
- [node-http-mitm-proxy](https://github.com/joeferner/node-http-mitm-proxy) — Node.js proxy
- [Ladybird Browser](https://ladybird.org/)
- [Servo Engine](https://servo.org/)
