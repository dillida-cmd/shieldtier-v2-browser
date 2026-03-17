# Wave 2a — Core Analysis: IPC Bridge + Analysis Engines

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Build the IPC bridge between the React renderer and the native C++ backend, then implement the four core analysis engines: YARA scanning, file analysis (PE focus), hash enrichment, and threat scoring. After this wave, a file captured by Wave 1's `DownloadCaptureFilter` can flow through the full analysis pipeline and produce a `ThreatVerdict`.

**Architecture:** The renderer sends JSON requests via `CefMessageRouter`. The native `MessageHandler` dispatches to analysis engines. Each engine produces `AnalysisEngineResult` (defined in `common/types.h`). The `ScoringEngine` aggregates all results into a final `ThreatVerdict`.

**Tech Stack:** CEF 145 (CefMessageRouter IPC), C++20, libyara (ExternalProject), pe-parse (CMake subdirectory), libcurl (CMake subdirectory), nlohmann_json

**Depends on:** Wave 1 (Chrono) -- uses `ShieldTierClient`, `ShieldTierApp`, `SessionManager`, `DownloadCaptureFilter`, `FileBuffer`, all shared types from `common/types.h`, and `Result<T>` from `common/result.h`.

---

## Execution Order

```
Task 1 (Nexus — IPC Bridge) ← do first, wires into ShieldTierClient/App
         │
         ▼
Task 2 (Rune — YARA)     ─┐
Task 3 (Scalpel — FileAn) ├── independent of each other
Task 4 (Oracle — Enrich)  ─┘
         │
         ▼
Task 5 (Verdict — Scoring) ← depends on Tasks 2-4 (consumes their result types)
```

Task 1 must be done first because it modifies `ShieldTierClient` and `ShieldTierApp` to add the message router, and later tasks need to register their IPC actions through the handler. Tasks 2, 3, and 4 are fully independent -- they each produce `AnalysisEngineResult` but have no cross-dependencies. Task 5 consumes the output of all engines and must be done last.

---

### Task 1: Nexus — IPC Bridge

**Codename:** Nexus

**Files:**
- Create: `src/native/ipc/message_handler.h`
- Create: `src/native/ipc/message_handler.cpp`
- Create: `src/native/ipc/ipc_protocol.h`
- Create: `src/native/app/shieldtier_renderer_app.h`
- Create: `src/native/app/shieldtier_renderer_app.cpp`
- Modify: `src/native/app/shieldtier_client.h`
- Modify: `src/native/app/shieldtier_client.cpp`
- Modify: `src/native/app/shieldtier_app.h`
- Modify: `src/native/app/shieldtier_app.cpp`
- Modify: `src/native/app/main.cpp`
- Modify: `src/native/CMakeLists.txt`

**What to build:**

CefMessageRouter provides async IPC between the renderer (JavaScript) and the browser process (C++). It requires setup on both sides:
- **Browser side:** `CefMessageRouterBrowserSide` created in the browser process, with a `Handler` that processes requests.
- **Renderer side:** `CefMessageRouterRendererSide` created in a separate `CefApp` subclass for the renderer process.

CEF runs multiple processes. `main.cpp` already calls `CefExecuteProcess` which handles subprocess dispatch, but we need to pass a renderer-aware `CefApp` to it so the renderer process gets its own message router config.

**IPC Protocol (`ipc_protocol.h`):**

```cpp
#pragma once

#include <string>
#include "common/json.h"

namespace shieldtier::ipc {

// Request: { "action": "...", "payload": {...} }
// Response: { "success": true/false, "data": {...}, "error": "..." }

struct IpcRequest {
    std::string action;
    json payload;
};

struct IpcResponse {
    bool success;
    json data;
    std::string error;
};

inline json make_success(const json& data = json::object()) {
    return json{{"success", true}, {"data", data}};
}

inline json make_error(const std::string& message) {
    return json{{"success", false}, {"error", message}, {"data", json::object()}};
}

inline IpcRequest parse_request(const std::string& raw) {
    auto j = parse_json_safe(raw);
    IpcRequest req;
    req.action = j.value("action", "");
    req.payload = j.value("payload", json::object());
    return req;
}

// Actions supported in Wave 2a:
constexpr const char* kActionNavigate = "navigate";
constexpr const char* kActionGetTabs = "get_tabs";
constexpr const char* kActionCloseTab = "close_tab";
constexpr const char* kActionAnalyzeDownload = "analyze_download";
constexpr const char* kActionGetAnalysisResult = "get_analysis_result";

}  // namespace shieldtier::ipc
```

**MessageHandler (`message_handler.h`):**

```cpp
#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include "include/cef_browser.h"
#include "include/wrapper/cef_message_router.h"

#include "browser/session_manager.h"
#include "ipc/ipc_protocol.h"

namespace shieldtier {

class MessageHandler : public CefMessageRouterBrowserSide::Handler {
public:
    explicit MessageHandler(SessionManager* session_manager);

    bool OnQuery(CefRefPtr<CefBrowser> browser,
                 CefRefPtr<CefFrame> frame,
                 int64_t query_id,
                 const CefString& request,
                 bool persistent,
                 CefRefPtr<Callback> callback) override;

    void OnQueryCanceled(CefRefPtr<CefBrowser> browser,
                         CefRefPtr<CefFrame> frame,
                         int64_t query_id) override;

private:
    json handle_navigate(CefRefPtr<CefBrowser> browser, const json& payload);
    json handle_get_tabs(const json& payload);
    json handle_close_tab(const json& payload);
    json handle_analyze_download(const json& payload);
    json handle_get_analysis_result(const json& payload);

    SessionManager* session_manager_;

    // Store pending analysis results keyed by SHA-256 hash
    std::unordered_map<std::string, json> analysis_results_;
};

}  // namespace shieldtier
```

**MessageHandler implementation (`message_handler.cpp`) key behavior:**

- `OnQuery` parses the JSON request string via `ipc::parse_request()`.
- Dispatches to `handle_*` methods based on `action` field.
- `handle_navigate`: calls `Navigation::load_url()` on the browser for `payload["url"]`.
- `handle_get_tabs`: calls `session_manager_->get_all_tabs()`, returns JSON array of tab info.
- `handle_close_tab`: calls `session_manager_->close_tab(payload["browser_id"])`.
- `handle_analyze_download`: placeholder that accepts a SHA-256 hash and triggers analysis pipeline (full wiring in Task 5). Returns immediately with `{ "queued": true, "sha256": "..." }`.
- `handle_get_analysis_result`: looks up cached result by SHA-256. Returns the `ThreatVerdict` JSON or `{ "status": "pending" }`.
- Unknown actions return `ipc::make_error("unknown_action")`.
- All handlers return JSON via `callback->Success(result.dump())` or `callback->Failure(error_code, error.dump())`.

**Renderer App (`shieldtier_renderer_app.h`):**

```cpp
#pragma once

#include "include/cef_app.h"
#include "include/cef_render_process_handler.h"
#include "include/wrapper/cef_message_router.h"

class ShieldTierRendererApp : public CefApp,
                               public CefRenderProcessHandler {
public:
    ShieldTierRendererApp() = default;

    CefRefPtr<CefRenderProcessHandler> GetRenderProcessHandler() override {
        return this;
    }

    void OnWebKitInitialized() override;

    void OnContextCreated(CefRefPtr<CefBrowser> browser,
                          CefRefPtr<CefFrame> frame,
                          CefRefPtr<CefV8Context> context) override;

    void OnContextReleased(CefRefPtr<CefBrowser> browser,
                           CefRefPtr<CefFrame> frame,
                           CefRefPtr<CefV8Context> context) override;

    bool OnProcessMessageReceived(CefRefPtr<CefBrowser> browser,
                                  CefRefPtr<CefFrame> frame,
                                  CefProcessId source_process,
                                  CefRefPtr<CefProcessMessage> message) override;

private:
    CefRefPtr<CefMessageRouterRendererSide> message_router_;

    IMPLEMENT_REFCOUNTING(ShieldTierRendererApp);
    DISALLOW_COPY_AND_ASSIGN(ShieldTierRendererApp);
};
```

**Renderer App implementation key behavior:**

- `OnWebKitInitialized()`: creates `CefMessageRouterRendererSide` with default config (query function `cefQuery`, cancel function `cefQueryCancel`).
- `OnContextCreated()`: calls `message_router_->OnContextCreated(browser, frame, context)`.
- `OnContextReleased()`: calls `message_router_->OnContextReleased(browser, frame, context)`.
- `OnProcessMessageReceived()`: delegates to `message_router_->OnProcessMessageReceived(...)`.

**Modifications to ShieldTierClient:**

Add `CefMessageRouterBrowserSide` as a member. Implement `OnProcessMessageReceived()` to delegate to it. In constructor, create the router and add a `MessageHandler` instance to it. Forward `OnBeforeClose()` to the router. The client must also implement `GetRequestHandler()` to override `OnBeforeBrowse` and forward to the router.

```cpp
// Add to shieldtier_client.h:
#include "include/wrapper/cef_message_router.h"
#include "ipc/message_handler.h"

// Add to class ShieldTierClient:
public:
    bool OnProcessMessageReceived(CefRefPtr<CefBrowser> browser,
                                  CefRefPtr<CefFrame> frame,
                                  CefProcessId source_process,
                                  CefRefPtr<CefProcessMessage> message) override;

private:
    CefRefPtr<CefMessageRouterBrowserSide> message_router_;
    std::unique_ptr<shieldtier::MessageHandler> message_handler_;
```

In the constructor:
```cpp
CefMessageRouterConfig config;
// defaults: query "cefQuery", cancel "cefQueryCancel"
message_router_ = CefMessageRouterBrowserSide::Create(config);
message_handler_ = std::make_unique<shieldtier::MessageHandler>(session_manager_.get());
message_router_->AddHandler(message_handler_.get(), false);
```

In `OnProcessMessageReceived`:
```cpp
return message_router_->OnProcessMessageReceived(browser, source_process, message);
```

In `OnBeforeClose`:
```cpp
message_router_->OnBeforeClose(browser);
```

**Modifications to ShieldTierApp:**

No changes needed. The browser-process app already works correctly. The renderer process app is a separate class.

**Modifications to main.cpp:**

Pass `ShieldTierRendererApp` to `CefExecuteProcess` for the renderer subprocess. The subprocess type is determined by CEF automatically. Approach: create a `ShieldTierRendererApp` and pass it as the app to `CefExecuteProcess`. The browser process then uses `ShieldTierApp` for `CefInitialize` as before.

```cpp
CefRefPtr<ShieldTierRendererApp> renderer_app(new ShieldTierRendererApp());
int exit_code = CefExecuteProcess(main_args, renderer_app.get(), nullptr);
if (exit_code >= 0) {
    return exit_code;
}
// ... rest of browser process init with ShieldTierApp ...
```

**CMakeLists.txt additions:**

```cmake
ipc/message_handler.cpp
app/shieldtier_renderer_app.cpp
```

Add to link libraries:
```cmake
# CefMessageRouter requires the wrapper library (already linked via libcef_dll_wrapper)
```

**Link against:** `libcef_dll_wrapper` (already linked, provides `CefMessageRouterBrowserSide/RendererSide`)

**Commit:** `feat(nexus): add IPC bridge — CefMessageRouter with JSON protocol and renderer-side handler`

---

### Task 2: Rune — YARA Engine

**Codename:** Rune

**Files:**
- Create: `src/native/analysis/yara/yara_engine.h`
- Create: `src/native/analysis/yara/yara_engine.cpp`
- Create: `src/native/analysis/yara/rule_manager.h`
- Create: `src/native/analysis/yara/rule_manager.cpp`
- Modify: `src/native/CMakeLists.txt`

**What to build:**

**RuleManager (`rule_manager.h`):**

```cpp
#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "common/result.h"

namespace shieldtier {

struct RuleSet {
    std::string name;
    std::string source;     // YARA rule text
    std::string origin;     // "builtin", "filesystem", "cloud"
};

class RuleManager {
public:
    RuleManager();

    Result<bool> load_from_directory(const std::string& path);
    Result<bool> add_rule(const std::string& name, const std::string& source,
                          const std::string& origin = "custom");

    std::vector<RuleSet> get_all_rules() const;
    size_t rule_count() const;

private:
    void load_builtin_rules();

    mutable std::mutex mutex_;
    std::vector<RuleSet> rules_;
};

}  // namespace shieldtier
```

**Built-in rules (embedded as string literals in `rule_manager.cpp`):**

Include 5 basic rules:
1. `shieldtier_pe_upx_packed` -- detects UPX-packed PE files (UPX magic bytes in section names)
2. `shieldtier_pe_suspicious_imports` -- detects PE files importing VirtualAlloc + WriteProcessMemory + CreateRemoteThread (process injection pattern)
3. `shieldtier_eicar_test` -- detects the EICAR test string
4. `shieldtier_powershell_encoded` -- detects base64-encoded PowerShell commands (-enc/-EncodedCommand patterns)
5. `shieldtier_macro_autoopen` -- detects Office macro auto-execution keywords (Auto_Open, AutoExec, Document_Open)

Each rule stored as a `constexpr const char*` in an anonymous namespace. Loaded in `RuleManager` constructor via `load_builtin_rules()`.

**YaraEngine (`yara_engine.h`):**

```cpp
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <yara.h>

#include "common/types.h"
#include "common/result.h"
#include "analysis/yara/rule_manager.h"

namespace shieldtier {

class YaraEngine {
public:
    YaraEngine();
    ~YaraEngine();

    YaraEngine(const YaraEngine&) = delete;
    YaraEngine& operator=(const YaraEngine&) = delete;

    Result<bool> initialize();

    // Compile all rules from the RuleManager. Must be called before scan.
    // Can be called again to recompile after rules change.
    Result<bool> compile_rules();

    // Scan a buffer. Thread-safe (yr_rules_scan_mem is thread-safe with
    // separate scan contexts). Returns findings with matched rule names,
    // metadata, and matched strings.
    Result<AnalysisEngineResult> scan(const FileBuffer& file);

    RuleManager& rule_manager() { return rule_manager_; }

private:
    static int scan_callback(YR_SCAN_CONTEXT* context, int message,
                             void* message_data, void* user_data);

    RuleManager rule_manager_;
    YR_RULES* compiled_rules_ = nullptr;
    std::mutex compile_mutex_;
    bool initialized_ = false;
};

}  // namespace shieldtier
```

**YaraEngine implementation key behavior:**

- Constructor: does not call `yr_initialize()` (deferred to `initialize()`).
- `initialize()`: calls `yr_initialize()` (global, ref-counted by libyara). Calls `compile_rules()`.
- `compile_rules()`: locks `compile_mutex_`. Creates `YR_COMPILER` via `yr_compiler_create()`. Iterates `rule_manager_.get_all_rules()`, adds each rule source via `yr_compiler_add_string()`. Gets compiled rules via `yr_compiler_get_rules()`. If `compiled_rules_` was previously set, `yr_rules_destroy()` the old one first. Destroys compiler.
- `scan()`: calls `yr_rules_scan_mem(compiled_rules_, file.ptr(), file.size(), 0, scan_callback, &findings, timeout_secs)`. Timeout: 30 seconds. Returns `AnalysisEngineResult` with `engine = AnalysisEngine::kYara`.
- `scan_callback()`: static callback. On `CALLBACK_MSG_RULE_MATCHING`, extract the `YR_RULE` name, tags, metadata (author, description, severity), and matched strings. Build a `Finding` for each matched rule. Severity mapping: check rule meta for "severity" field, default to `Severity::kMedium`.
- Destructor: `yr_rules_destroy()` if set, then `yr_finalize()`.

**Thread safety:** `yr_rules_scan_mem` is thread-safe when called with different user_data pointers. The compiled rules (`YR_RULES*`) are immutable after compilation and can be shared across threads. Only `compile_rules()` needs the mutex.

**CMakeLists.txt additions:**

```cmake
analysis/yara/yara_engine.cpp
analysis/yara/rule_manager.cpp
```

Add to link:
```cmake
target_link_libraries(shieldtier PRIVATE yara)
```

The `yara` imported target is already defined in the top-level `CMakeLists.txt` via `ExternalProject`. It provides `libyara.a` and the include path to `<yara.h>`.

**Link against:** `yara` (imported static library from ExternalProject)

**Commit:** `feat(rune): add YARA engine — rule manager with 5 built-in rules, thread-safe scanning`

---

### Task 3: Scalpel — File Analysis

**Codename:** Scalpel

**Files:**
- Create: `src/native/analysis/fileanalysis/pe_analyzer.h`
- Create: `src/native/analysis/fileanalysis/pe_analyzer.cpp`
- Create: `src/native/analysis/fileanalysis/file_analyzer.h`
- Create: `src/native/analysis/fileanalysis/file_analyzer.cpp`
- Modify: `src/native/CMakeLists.txt`

**What to build:**

**PeAnalyzer (`pe_analyzer.h`):**

```cpp
#pragma once

#include <string>
#include <vector>

#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

struct PeSection {
    std::string name;
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t characteristics;
    double entropy;
};

struct PeImport {
    std::string dll_name;
    std::string function_name;
};

struct PeSecurityFeatures {
    bool aslr;         // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    bool dep;          // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    bool cfg;          // IMAGE_DLLCHARACTERISTICS_GUARD_CF
    bool seh;          // NOT IMAGE_DLLCHARACTERISTICS_NO_SEH
    bool authenticode; // has a security directory entry
};

struct PeInfo {
    bool is_64bit;
    bool is_dll;
    uint32_t entry_point;
    uint16_t subsystem;
    std::string compile_timestamp;
    std::vector<PeSection> sections;
    std::vector<PeImport> imports;
    PeSecurityFeatures security;
    std::vector<std::string> suspicious_imports;
};

class PeAnalyzer {
public:
    // Analyze a PE buffer. Returns PeInfo on success.
    Result<PeInfo> analyze(const FileBuffer& file);

    // Generate findings from PeInfo.
    std::vector<Finding> generate_findings(const PeInfo& info);

private:
    double calculate_section_entropy(const uint8_t* data, size_t size);
    std::vector<std::string> check_suspicious_imports(const std::vector<PeImport>& imports);
};

}  // namespace shieldtier
```

**PeAnalyzer implementation key behavior:**

- `analyze()`: uses pe-parse to open the buffer (via `peparse::ParsePEFromBuffer()`). Extracts:
  - **Machine type / bitness**: from `IMAGE_FILE_HEADER.Machine` (0x8664 = 64-bit, 0x14c = 32-bit)
  - **DLL flag**: `IMAGE_FILE_HEADER.Characteristics & IMAGE_FILE_DLL`
  - **Entry point**: `IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint`
  - **Subsystem**: console, GUI, etc.
  - **Compile timestamp**: `IMAGE_FILE_HEADER.TimeDateStamp` formatted as ISO 8601
  - **Sections**: iterate sections, extract name, virtual size/addr, raw size, characteristics, compute entropy per section
  - **Imports**: iterate import directory, extract DLL + function names
  - **Security features**: check `DllCharacteristics` flags for ASLR, DEP, CFG, SEH. Check if `IMAGE_DIRECTORY_ENTRY_SECURITY` has non-zero size for Authenticode.
- `check_suspicious_imports()`: flag known suspicious API combinations:
  - Process injection: `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
  - Code injection: `NtCreateSection` + `NtMapViewOfSection`
  - Process hollowing: `CreateProcessA/W` + `NtUnmapViewOfSection`
  - Keylogging: `SetWindowsHookExA/W` + `GetAsyncKeyState`
  - Anti-debug: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`
  - Persistence: `RegSetValueExA/W` + `CreateServiceA/W`
  - Network: `InternetOpenA/W` + `URLDownloadToFileA/W`
  Returns a list of human-readable descriptions of matched suspicious patterns.
- `generate_findings()`: converts PeInfo into `Finding` objects:
  - High entropy section (> 7.0) -> `Severity::kMedium` ("Packed or encrypted section")
  - Missing ASLR/DEP -> `Severity::kLow` ("Security feature not enabled")
  - Each suspicious import pattern -> `Severity::kMedium` to `Severity::kHigh`
  - Timestomping (compile time in future or before 2000) -> `Severity::kMedium`
- `calculate_section_entropy()`: Shannon entropy over the byte distribution.

**FileAnalyzer (`file_analyzer.h`):**

```cpp
#pragma once

#include <string>
#include <vector>

#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

enum class FileType {
    kPE,
    kPDF,
    kZIP,
    kOfficeDoc,  // OLE2 (doc, xls, ppt)
    kOfficeXml,  // OOXML (docx, xlsx, pptx) — detected as ZIP
    kELF,
    kMachO,
    kScript,
    kUnknown
};

struct FileInfo {
    FileType type;
    std::string type_name;
    size_t size;
    double entropy;
    std::string sha256;
    std::string md5;
    std::vector<std::string> extracted_strings;
    size_t printable_string_count;
    size_t url_count;
    size_t ip_count;
};

class FileAnalyzer {
public:
    // Full analysis: detect type, compute hashes, extract strings, dispatch
    // to format-specific analyzer.
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

    // Detect file type from magic bytes.
    static FileType detect_type(const uint8_t* data, size_t size);
    static std::string file_type_name(FileType type);

    // Compute Shannon entropy for entire buffer.
    static double calculate_entropy(const uint8_t* data, size_t size);

    // Extract printable ASCII strings (min length 4).
    static std::vector<std::string> extract_strings(const uint8_t* data,
                                                     size_t size,
                                                     size_t min_length = 4,
                                                     size_t max_strings = 1000);

    // Compute MD5 hash (for enrichment lookups).
    static std::string compute_md5(const uint8_t* data, size_t size);

private:
    std::vector<Finding> generate_findings(const FileInfo& info);
};

}  // namespace shieldtier
```

**FileAnalyzer implementation key behavior:**

- `detect_type()`: check magic bytes at offset 0:
  - `4D 5A` (MZ) -> `kPE`
  - `25 50 44 46` (%PDF) -> `kPDF`
  - `50 4B 03 04` (PK\x03\x04) -> `kZIP` (then check for OOXML by looking for `[Content_Types].xml` in first few bytes or just report ZIP)
  - `D0 CF 11 E0` -> `kOfficeDoc` (OLE2 Compound Document)
  - `7F 45 4C 46` (\x7FELF) -> `kELF`
  - `CF FA ED FE` or `CE FA ED FE` or `FE ED FA CF/CE` -> `kMachO`
  - Check for script shebangs (`#!`) or known script patterns -> `kScript`
  - Otherwise -> `kUnknown`

- `analyze()`: calls `detect_type()`, `calculate_entropy()`, `extract_strings()`, `compute_md5()`. SHA-256 is already in `FileBuffer.sha256`. If type is `kPE`, creates a `PeAnalyzer` and delegates. Combines all findings into an `AnalysisEngineResult` with `engine = AnalysisEngine::kFileAnalysis`.

- `extract_strings()`: scans bytes for runs of printable ASCII (0x20-0x7E) of at least `min_length`. Also extracts UTF-16LE strings (alternating printable + 0x00 bytes). Caps at `max_strings`. After extraction, counts URLs (regex: `https?://`) and IPs (regex: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`).

- `calculate_entropy()`: standard Shannon entropy. Count byte frequencies, compute `-sum(p * log2(p))`. Range 0.0 (uniform) to 8.0 (random). Values > 7.5 suggest encryption or compression.

- `compute_md5()`: use CommonCrypto `CC_MD5` on macOS, OpenSSL `EVP_MD_CTX` on Linux/Windows. Needed for VirusTotal lookups (VT accepts MD5/SHA1/SHA256).

- `generate_findings()`:
  - High overall entropy (> 7.2) -> `Severity::kMedium` ("File appears packed or encrypted")
  - URLs found in strings -> `Severity::kInfo` (list them in metadata)
  - IPs found in strings -> `Severity::kLow` (list them in metadata)
  - Very few printable strings relative to size -> `Severity::kLow` ("Low string density suggests packing")

**CMakeLists.txt additions:**

```cmake
analysis/fileanalysis/pe_analyzer.cpp
analysis/fileanalysis/file_analyzer.cpp
```

Add to link:
```cmake
target_link_libraries(shieldtier PRIVATE pe-parse)
```

The `pe-parse` target is already available from the top-level `add_subdirectory(third_party/pe-parse)`.

**Link against:** `pe-parse` (CMake subdirectory target)

**Commit:** `feat(scalpel): add file analysis — PE analyzer with pe-parse, magic detection, entropy, strings`

---

### Task 4: Oracle — Enrichment

**Codename:** Oracle

**Files:**
- Create: `src/native/analysis/enrichment/http_client.h`
- Create: `src/native/analysis/enrichment/http_client.cpp`
- Create: `src/native/analysis/enrichment/enrichment_manager.h`
- Create: `src/native/analysis/enrichment/enrichment_manager.cpp`
- Modify: `src/native/CMakeLists.txt`

**What to build:**

**HttpClient (`http_client.h`):**

```cpp
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

struct HttpResponse {
    int status_code;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    // Synchronous GET with JSON response parsing.
    Result<json> get_json(const std::string& url,
                          const std::unordered_map<std::string, std::string>& headers = {});

    // Synchronous POST with JSON body and response.
    Result<json> post_json(const std::string& url,
                           const json& body,
                           const std::unordered_map<std::string, std::string>& headers = {});

    // Raw GET.
    Result<HttpResponse> get(const std::string& url,
                             const std::unordered_map<std::string, std::string>& headers = {});

    void set_timeout(long timeout_seconds);
    void set_user_agent(const std::string& user_agent);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace shieldtier
```

**HttpClient implementation key behavior:**

- Uses libcurl's easy interface (`curl_easy_init`, `curl_easy_perform`).
- PIMPL pattern to hide curl headers from consumers.
- Constructor: `curl_global_init(CURL_GLOBAL_DEFAULT)` (once, via `std::call_once`). Creates a `CURL*` handle.
- `get_json()`: sets `CURLOPT_URL`, sets custom headers via `curl_slist`, sets write callback to accumulate response body into `std::string`. Performs request. Parses response body as JSON. Returns `Result<json>`.
- `post_json()`: same as get, but sets `CURLOPT_POST`, `CURLOPT_POSTFIELDS` with `body.dump()`, adds `Content-Type: application/json` header.
- `get()`: raw GET, returns `HttpResponse` with status code, body, and response headers.
- Default timeout: 15 seconds.
- Default User-Agent: `"ShieldTier/2.0"`.
- SSL verification enabled (libcurl defaults).
- Destructor: `curl_easy_cleanup()`.

**EnrichmentManager (`enrichment_manager.h`):**

```cpp
#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/types.h"
#include "common/result.h"
#include "analysis/enrichment/http_client.h"

namespace shieldtier {

struct EnrichmentConfig {
    std::string virustotal_api_key;
    std::string abuseipdb_api_key;
    std::string otx_api_key;
    // URLhaus is public, no key needed
};

struct ProviderResult {
    std::string provider_name;
    bool found;
    int detection_count;      // VT: positives, AbuseIPDB: abuse confidence score
    int total_engines;        // VT: total scanners
    std::string reputation;   // "clean", "suspicious", "malicious"
    json raw_response;
};

class EnrichmentManager {
public:
    explicit EnrichmentManager(const EnrichmentConfig& config);

    // Query all configured providers by file hash.
    // Returns AnalysisEngineResult with findings from each provider.
    Result<AnalysisEngineResult> enrich_by_hash(const std::string& sha256,
                                                 const std::string& md5 = "");

    // Query a single provider.
    Result<ProviderResult> query_virustotal(const std::string& hash);
    Result<ProviderResult> query_abuseipdb(const std::string& ip);
    Result<ProviderResult> query_otx(const std::string& hash);
    Result<ProviderResult> query_urlhaus(const std::string& hash);

    void set_config(const EnrichmentConfig& config);

private:
    struct CacheEntry {
        ProviderResult result;
        std::chrono::steady_clock::time_point expires_at;
    };

    std::string get_cache_key(const std::string& provider,
                              const std::string& indicator);
    void cache_result(const std::string& key, const ProviderResult& result);
    std::optional<ProviderResult> get_cached(const std::string& key);

    std::vector<Finding> generate_findings(
        const std::vector<ProviderResult>& results);

    EnrichmentConfig config_;
    HttpClient http_client_;

    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
    static constexpr auto kCacheTtl = std::chrono::minutes(15);

    // Rate limiting: track last request time per provider
    mutable std::mutex rate_mutex_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_request_;
    void rate_limit(const std::string& provider);
};

}  // namespace shieldtier
```

**EnrichmentManager implementation key behavior:**

- `enrich_by_hash()`: queries each configured provider (only if API key is set). Collects `ProviderResult` from each. Generates `Finding` objects. Returns `AnalysisEngineResult` with `engine = AnalysisEngine::kEnrichment`.

- `query_virustotal()`: `GET https://www.virustotal.com/api/v3/files/{hash}` with header `x-apikey: {key}`. Parse response: `data.attributes.last_analysis_stats` for `malicious`, `suspicious`, `harmless`, `undetected` counts. `detection_count = malicious + suspicious`. `total_engines = sum of all`. Set reputation based on ratio.

- `query_otx()`: `GET https://otx.alienvault.com/api/v1/indicators/file/{hash}/general` with header `X-OTX-API-KEY: {key}`. Parse `pulse_info.count` for pulse count. If pulses > 0, mark as suspicious/malicious.

- `query_urlhaus()`: `POST https://urlhaus-api.abuse.ch/v1/payload/` with form data `sha256_hash={hash}`. No API key needed. Parse response for `query_status = "ok"` and `urls_online` count.

- `query_abuseipdb()`: for IP enrichment (not hash-based, but included for URL/domain analysis in future). `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}` with header `Key: {key}`. Parse `data.abuseConfidenceScore`.

- `rate_limit()`: per-provider minimum interval. VT free tier: 4 requests/minute -> 15 seconds between requests. OTX: 1 second. URLhaus: 1 second. AbuseIPDB: 1 second. If called too soon, `std::this_thread::sleep_for()` the remaining time.

- `cache_result()` / `get_cached()`: simple in-memory cache with 15-minute TTL. Keyed by `"provider:indicator"`.

- `generate_findings()`: for each provider result:
  - VT: if detection_count > 5, `Severity::kHigh` ("Detected by N/M engines on VirusTotal"). If 1-5, `Severity::kMedium`. If 0, `Severity::kInfo` ("Clean on VirusTotal").
  - OTX: if pulse_count > 0, `Severity::kMedium` ("Found in N OTX pulses").
  - URLhaus: if found, `Severity::kHigh` ("Listed on URLhaus as malware distribution").

**CMakeLists.txt additions:**

```cmake
analysis/enrichment/http_client.cpp
analysis/enrichment/enrichment_manager.cpp
```

Add to link:
```cmake
target_link_libraries(shieldtier PRIVATE CURL::libcurl)
```

The `CURL::libcurl` target is available from `add_subdirectory(third_party/curl)`.

**Link against:** `CURL::libcurl` (CMake subdirectory target)

**Commit:** `feat(oracle): add enrichment — VT, OTX, URLhaus lookups with caching and rate limiting`

---

### Task 5: Verdict — Scoring Engine

**Codename:** Verdict

**Files:**
- Create: `src/native/scoring/scoring_engine.h`
- Create: `src/native/scoring/scoring_engine.cpp`
- Modify: `src/native/ipc/message_handler.h`
- Modify: `src/native/ipc/message_handler.cpp`
- Modify: `src/native/CMakeLists.txt`

**What to build:**

**ScoringEngine (`scoring_engine.h`):**

```cpp
#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

struct EngineWeight {
    AnalysisEngine engine;
    double weight;  // 0.0 - 1.0
};

class ScoringEngine {
public:
    ScoringEngine();

    // Aggregate results from all engines into a final verdict.
    Result<ThreatVerdict> score(
        const std::vector<AnalysisEngineResult>& results);

    // Override default weights (useful for tier-specific tuning).
    void set_weights(const std::vector<EngineWeight>& weights);

    // Get current weight configuration.
    std::vector<EngineWeight> get_weights() const;

private:
    // Compute raw score (0-100) for a single engine's results.
    double compute_engine_score(const AnalysisEngineResult& result);

    // Map severity to numeric weight.
    static double severity_weight(Severity severity);

    // Determine verdict from threat score.
    static Verdict classify(int threat_score);

    // Determine risk level string.
    static std::string risk_level(int threat_score);

    // Determine confidence based on how many engines contributed.
    static double compute_confidence(
        const std::vector<AnalysisEngineResult>& results,
        int engines_with_findings);

    // Extract MITRE ATT&CK technique IDs from finding metadata.
    static std::vector<std::string> extract_mitre_techniques(
        const std::vector<AnalysisEngineResult>& results);

    std::unordered_map<AnalysisEngine, double> weights_;
};

}  // namespace shieldtier
```

**ScoringEngine implementation key behavior:**

- Constructor sets default weights:
  ```
  kYara:         0.30
  kSandbox:      0.25
  kFileAnalysis:  0.15
  kAdvanced:     0.15
  kEnrichment:   0.10
  kContent:      0.05
  ```
  (Sandbox, Advanced, Content engines are not built in Wave 2a, so their weight is redistributed proportionally among present engines during scoring.)

- `score()`:
  1. For each `AnalysisEngineResult`, compute an engine-level score (0-100) via `compute_engine_score()`.
  2. Weighted average: `threat_score = sum(engine_score * weight) / sum(active_weights)`. Only engines with results present are included ("active"). Weights of missing engines are excluded from normalization.
  3. Clamp to 0-100 integer.
  4. `classify()` to get `Verdict`:
     - `threat_score < 25` -> `Verdict::kClean`
     - `25 <= threat_score <= 65` -> `Verdict::kSuspicious`
     - `threat_score > 65` -> `Verdict::kMalicious`
  5. `risk_level()`:
     - 0-10: `"none"`
     - 11-25: `"low"`
     - 26-50: `"medium"`
     - 51-75: `"high"`
     - 76-100: `"critical"`
  6. `compute_confidence()`: based on engine coverage. If only 1 engine reported, confidence = 0.3. If 2 engines, 0.5. If 3+, scales linearly up to 0.95. If an engine with high-severity findings is corroborated by another engine, boost confidence by 0.1. Cap at 1.0.
  7. Collect all findings from all engine results into the verdict's `findings` vector.
  8. `extract_mitre_techniques()`: scan finding metadata for `"mitre"` or `"technique_id"` keys. Deduplicate.

- `compute_engine_score()`:
  - Sum severity weights of all findings: `kInfo=2, kLow=10, kMedium=25, kHigh=50, kCritical=80`.
  - Cap at 100.
  - If the engine failed (`success == false`), return 0 (don't penalize for failure).

- `severity_weight()`:
  - `kInfo` -> 2.0
  - `kLow` -> 10.0
  - `kMedium` -> 25.0
  - `kHigh` -> 50.0
  - `kCritical` -> 80.0

**Integration with MessageHandler:**

After this task, wire the full analysis pipeline into the message handler:

- `handle_analyze_download()` now:
  1. Looks up the `FileBuffer` from `DownloadCaptureFilter` (stored by the request handler in a shared map keyed by SHA-256).
  2. Creates a `std::thread` for async analysis.
  3. Runs YARA scan (`YaraEngine::scan()`), file analysis (`FileAnalyzer::analyze()`), and enrichment (`EnrichmentManager::enrich_by_hash()`).
  4. Passes all `AnalysisEngineResult` to `ScoringEngine::score()`.
  5. Stores the `ThreatVerdict` in `analysis_results_` keyed by SHA-256.
  6. Returns `{ "queued": true, "sha256": "..." }` immediately.

- `handle_get_analysis_result()`: looks up by SHA-256, returns the JSON-serialized `ThreatVerdict` or `{ "status": "pending" }`.

Add to MessageHandler:
```cpp
// Add to message_handler.h private members:
std::unique_ptr<YaraEngine> yara_engine_;
std::unique_ptr<FileAnalyzer> file_analyzer_;
std::unique_ptr<EnrichmentManager> enrichment_manager_;
std::unique_ptr<ScoringEngine> scoring_engine_;
```

Initialize all engines in `MessageHandler` constructor. `YaraEngine::initialize()` called once. `EnrichmentManager` constructed with config (API keys loaded from environment variables or empty for now).

**CMakeLists.txt additions:**

```cmake
scoring/scoring_engine.cpp
```

No additional link dependencies (scoring only uses types from `common/types.h`).

**Link against:** nothing additional (uses existing types)

**Commit:** `feat(verdict): add scoring engine — weighted aggregation, MITRE extraction, full pipeline wiring`

---

## Final CMakeLists.txt State

After all 5 tasks, `src/native/CMakeLists.txt` should have:

```cmake
set(SHIELDTIER_SOURCES
    app/main.cpp
    app/shieldtier_app.cpp
    app/shieldtier_client.cpp
    app/shieldtier_renderer_app.cpp
    browser/request_handler.cpp
    browser/response_filter.cpp
    browser/download_handler.cpp
    browser/session_manager.cpp
    browser/navigation.cpp
    ipc/message_handler.cpp
    analysis/yara/yara_engine.cpp
    analysis/yara/rule_manager.cpp
    analysis/fileanalysis/pe_analyzer.cpp
    analysis/fileanalysis/file_analyzer.cpp
    analysis/enrichment/http_client.cpp
    analysis/enrichment/enrichment_manager.cpp
    scoring/scoring_engine.cpp
)

target_link_libraries(shieldtier PRIVATE
    libcef_dll_wrapper
    ${CEF_LIBRARY}
    nlohmann_json::nlohmann_json
    yara
    pe-parse
    CURL::libcurl
)
```

## Data Flow Summary

```
Renderer (React UI)
    │
    ├─ cefQuery('{"action":"analyze_download","payload":{"sha256":"abc123"}}')
    │
    ▼
CefMessageRouterRendererSide
    │
    ▼  (IPC process message)
CefMessageRouterBrowserSide
    │
    ▼
MessageHandler::OnQuery()
    │
    ├─ parse_request() -> IpcRequest{action, payload}
    │
    ├─ handle_analyze_download():
    │     │
    │     ├─ Look up FileBuffer by SHA-256 (from DownloadCaptureFilter)
    │     │
    │     ├─ std::thread:
    │     │     ├─ YaraEngine::scan(file)        -> AnalysisEngineResult
    │     │     ├─ FileAnalyzer::analyze(file)    -> AnalysisEngineResult
    │     │     ├─ EnrichmentManager::enrich(sha) -> AnalysisEngineResult
    │     │     │
    │     │     ▼
    │     │   ScoringEngine::score(all_results)   -> ThreatVerdict
    │     │     │
    │     │     ▼
    │     │   Store in analysis_results_[sha256]
    │     │
    │     └─ Return: {"success":true,"data":{"queued":true,"sha256":"..."}}
    │
    └─ handle_get_analysis_result():
          │
          └─ Return: {"success":true,"data":{...ThreatVerdict JSON...}}
               or:   {"success":true,"data":{"status":"pending"}}
```

## Verification

After all tasks, the build should succeed with:

```bash
cmake -G "Ninja" -DCEF_ROOT=/path/to/cef -B build
ninja -C build
```

New source files compile cleanly. The binary links against libyara, pe-parse, and libcurl in addition to existing CEF + nlohmann_json dependencies. The renderer subprocess handles `cefQuery` calls and routes them through the message router to the browser process.
