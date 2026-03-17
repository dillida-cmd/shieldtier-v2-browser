# Wave 1 — Chrono: CEF Shell Browser Engine

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Build the core CEF browser handlers that replace Electron — streaming response interception, download suppression, network policy enforcement, per-tab session isolation, and navigation controls.

**Architecture:** ShieldTierClient dispatches to handler classes. CefResponseFilter intercepts downloads in-memory (no disk writes). CefRequestHandler blocks private IPs and unsafe schemes. Each tab gets an isolated CefRequestContext with its own cookies/cache.

**Tech Stack:** CEF 145, C++20, CommonCrypto (macOS) / OpenSSL (Linux/Win) for SHA-256

---

### Task 1: Request Handler — Network Policy Enforcement

**Files:**
- Create: `src/native/browser/request_handler.h`
- Create: `src/native/browser/request_handler.cpp`

**What to build:**
ShieldTierRequestHandler : CefRequestHandler

Implements:
- `OnBeforeBrowse()` — block `javascript:`, `vbscript:`, `data:text/html` schemes; block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16 — except localhost for dev)
- `OnCertificateError()` — allow all SSL errors (malware sites have bad certs, log them)
- `GetResourceRequestHandler()` — return `this` (also inherits CefResourceRequestHandler)

Private IP check: parse the hostname, resolve to IP if needed, check against CIDR ranges. Use `inet_pton` for parsing.

```cpp
class ShieldTierRequestHandler : public CefRequestHandler,
                                  public CefResourceRequestHandler {
public:
    // CefRequestHandler
    bool OnBeforeBrowse(CefRefPtr<CefBrowser> browser,
                        CefRefPtr<CefFrame> frame,
                        CefRefPtr<CefRequest> request,
                        bool user_gesture,
                        bool is_redirect) override;

    bool OnCertificateError(CefRefPtr<CefBrowser> browser,
                            cef_errorcode_t cert_error,
                            const CefString& request_url,
                            CefRefPtr<CefSSLInfo> ssl_info,
                            CefRefPtr<CefCallback> callback) override;

    CefRefPtr<CefResourceRequestHandler> GetResourceRequestHandler(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefRefPtr<CefRequest> request,
        bool is_navigation,
        bool is_download,
        const CefString& request_initiator,
        bool& disable_default_handling) override;

    // CefResourceRequestHandler
    CefRefPtr<CefResponseFilter> GetResourceResponseFilter(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefRefPtr<CefRequest> request,
        CefRefPtr<CefResponse> response) override;

private:
    bool is_private_ip(const std::string& host);
    bool is_blocked_scheme(const std::string& url);

    IMPLEMENT_REFCOUNTING(ShieldTierRequestHandler);
    DISALLOW_COPY_AND_ASSIGN(ShieldTierRequestHandler);
};
```

**Commit:** `feat(chrono): add request handler — block private IPs, unsafe schemes, allow cert errors`

---

### Task 2: Response Filter — Streaming Download Interception

**Files:**
- Create: `src/native/browser/response_filter.h`
- Create: `src/native/browser/response_filter.cpp`

**What to build:**
Two CefResponseFilter implementations:

1. **DownloadCaptureFilter** (< 500MB): Accumulates all bytes in `std::vector<uint8_t>` + incremental SHA-256. Pass-through bytes to output buffer unchanged. On completion (data_in_size == 0), finalize hash.

2. **StreamingHashFilter** (>= 500MB or unknown size): Only hashes incrementally, does not accumulate. Pass-through bytes unchanged.

Download detection (called from GetResourceResponseFilter in request_handler):
- `Content-Disposition: attachment`
- Binary MIME types: `application/octet-stream`, `x-msdownload`, `x-executable`, `zip`, `rar`, `7z-compressed`, `pdf`, `x-dosexec`
- URL extensions: `.exe`, `.dll`, `.scr`, `.msi`, `.zip`, `.rar`, `.7z`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.hta`, `.iso`, `.img`, `.cab`, `.lnk`

SHA-256: Use `CC_SHA256` on macOS, OpenSSL `EVP_DigestUpdate` on Linux/Windows.

```cpp
class DownloadCaptureFilter : public CefResponseFilter {
public:
    explicit DownloadCaptureFilter(const std::string& url, const std::string& mime_type);

    bool InitFilter() override;
    FilterStatus Filter(void* data_in, size_t data_in_size, size_t& data_in_read,
                        void* data_out, size_t data_out_size, size_t& data_out_written) override;

    const std::vector<uint8_t>& captured_data() const;
    std::string sha256_hex() const;
    const std::string& url() const;
    const std::string& mime_type() const;

private:
    std::string url_;
    std::string mime_type_;
    std::vector<uint8_t> buffer_;
    // Platform-specific SHA-256 context
    bool complete_ = false;
    std::string sha256_hex_;

    IMPLEMENT_REFCOUNTING(DownloadCaptureFilter);
    DISALLOW_COPY_AND_ASSIGN(DownloadCaptureFilter);
};

class StreamingHashFilter : public CefResponseFilter {
public:
    explicit StreamingHashFilter(const std::string& url);

    bool InitFilter() override;
    FilterStatus Filter(void* data_in, size_t data_in_size, size_t& data_in_read,
                        void* data_out, size_t data_out_size, size_t& data_out_written) override;

    std::string sha256_hex() const;

private:
    std::string url_;
    bool complete_ = false;
    std::string sha256_hex_;

    IMPLEMENT_REFCOUNTING(StreamingHashFilter);
    DISALLOW_COPY_AND_ASSIGN(StreamingHashFilter);
};
```

Helper: `bool is_download_response(CefRefPtr<CefRequest>, CefRefPtr<CefResponse>)` — checks MIME + Content-Disposition + URL extension.

**Commit:** `feat(chrono): add response filters — streaming download capture with SHA-256`

---

### Task 3: Download Handler — Suppress Disk Writes

**Files:**
- Create: `src/native/browser/download_handler.h`
- Create: `src/native/browser/download_handler.cpp`

**What to build:**
ShieldTierDownloadHandler : CefDownloadHandler

- `OnBeforeDownload()` — do NOT call `callback->Continue()`. This suppresses the file save dialog and disk write. Log the download URL + suggested filename.
- `OnDownloadUpdated()` — if download somehow started (shouldn't happen since we don't call Continue), cancel it via `callback->Cancel()`.

```cpp
class ShieldTierDownloadHandler : public CefDownloadHandler {
public:
    bool CanDownload(CefRefPtr<CefBrowser> browser,
                     const CefString& url,
                     const CefString& request_method) override;

    void OnBeforeDownload(CefRefPtr<CefBrowser> browser,
                          CefRefPtr<CefDownloadItem> download_item,
                          const CefString& suggested_name,
                          CefRefPtr<CefBeforeDownloadCallback> callback) override;

    void OnDownloadUpdated(CefRefPtr<CefBrowser> browser,
                           CefRefPtr<CefDownloadItem> download_item,
                           CefRefPtr<CefDownloadItemCallback> callback) override;

private:
    IMPLEMENT_REFCOUNTING(ShieldTierDownloadHandler);
    DISALLOW_COPY_AND_ASSIGN(ShieldTierDownloadHandler);
};
```

**Commit:** `feat(chrono): add download handler — suppress disk writes, cancel unexpected downloads`

---

### Task 4: Session Manager — Per-Tab Isolation

**Files:**
- Create: `src/native/browser/session_manager.h`
- Create: `src/native/browser/session_manager.cpp`

**What to build:**
SessionManager manages per-tab CefBrowser instances with isolated CefRequestContext.

- `create_tab(url, in_memory)` — creates a new CefBrowser with a unique CefRequestContext. If `in_memory`, cache_path is empty. Otherwise, cache_path is `root_cache_path/tab_<id>`.
- `close_tab(browser_id)` — closes the browser and cleans up context.
- `get_browser(browser_id)` — returns CefRefPtr<CefBrowser>.
- `get_all_browsers()` — returns all active browsers.
- `clear_tab_data(browser_id)` — clears cookies/cache for that tab.

Root cache path: `/tmp/shieldtier/cache` (configurable).

Each CefRequestContext gets its own `CefCookieManager` via `GetCookieManager()` — isolation is automatic when using separate request contexts.

```cpp
class SessionManager {
public:
    explicit SessionManager(const std::string& root_cache_path);

    struct TabInfo {
        int browser_id;
        CefRefPtr<CefBrowser> browser;
        CefRefPtr<CefRequestContext> context;
        bool in_memory;
    };

    void create_tab(const std::string& url, bool in_memory,
                    CefRefPtr<CefClient> client);
    void close_tab(int browser_id);
    CefRefPtr<CefBrowser> get_browser(int browser_id);
    std::vector<TabInfo> get_all_tabs() const;
    void clear_tab_data(int browser_id);

    void on_browser_created(CefRefPtr<CefBrowser> browser);
    void on_browser_closed(CefRefPtr<CefBrowser> browser);

private:
    std::string root_cache_path_;
    int next_tab_id_ = 1;
    std::unordered_map<int, TabInfo> tabs_;
};
```

**Commit:** `feat(chrono): add session manager — per-tab CefRequestContext isolation`

---

### Task 5: Navigation Controls

**Files:**
- Create: `src/native/browser/navigation.h`
- Create: `src/native/browser/navigation.cpp`

**What to build:**
Navigation helper class wrapping CefBrowser navigation methods. The React UI will call these through the IPC bridge (wired in Wave 2).

```cpp
class Navigation {
public:
    static void go_back(CefRefPtr<CefBrowser> browser);
    static void go_forward(CefRefPtr<CefBrowser> browser);
    static void reload(CefRefPtr<CefBrowser> browser);
    static void stop(CefRefPtr<CefBrowser> browser);
    static void load_url(CefRefPtr<CefBrowser> browser, const std::string& url);
    static std::string get_url(CefRefPtr<CefBrowser> browser);
    static std::string get_title(CefRefPtr<CefBrowser> browser);
    static bool can_go_back(CefRefPtr<CefBrowser> browser);
    static bool can_go_forward(CefRefPtr<CefBrowser> browser);
    static bool is_loading(CefRefPtr<CefBrowser> browser);
    static double get_zoom_level(CefRefPtr<CefBrowser> browser);
    static void set_zoom_level(CefRefPtr<CefBrowser> browser, double level);
};
```

These are thin wrappers, but they centralize the navigation API for IPC dispatch and provide a clean interface for the rest of the native code.

**Commit:** `feat(chrono): add navigation controls — back, forward, reload, stop, zoom`

---

### Task 6: Integration — Wire Handlers into ShieldTierClient

**Files:**
- Modify: `src/native/app/shieldtier_client.h`
- Modify: `src/native/app/shieldtier_client.cpp`
- Modify: `src/native/app/shieldtier_app.cpp`
- Modify: `src/native/app/main.cpp`
- Modify: `src/native/CMakeLists.txt`

**What to do:**

1. **ShieldTierClient**: Add handler members and return them from Get*Handler():
   - `GetRequestHandler()` → `ShieldTierRequestHandler`
   - `GetDownloadHandler()` → `ShieldTierDownloadHandler`
   - Add `SessionManager` as a member, forward OnAfterCreated/OnBeforeClose to it

2. **ShieldTierApp::OnContextInitialized()**: Configure CefSettings with `root_cache_path`. Create initial tab via SessionManager instead of direct CefBrowserHost::CreateBrowser.

3. **main.cpp**: Set `root_cache_path` in CefSettings. Add WebRTC disable flags via command line.

4. **CMakeLists.txt**: Add all new source files to SHIELDTIER_SOURCES.

**Commit:** `feat(chrono): integrate all handlers into ShieldTierClient`

---

### Task 7: Build Verification

Run cmake configure + ninja build. Fix any compile errors. Verify the binary links successfully with all new handlers.

**Commit:** `fix(chrono): resolve build issues` (if needed)

---

## Execution Order

```
Task 1 (request_handler) ─┐
Task 2 (response_filter)  ├── can run in parallel (independent files)
Task 3 (download_handler) ┤
Task 4 (session_manager)  ┤
Task 5 (navigation)       ─┘
         │
         ▼
Task 6 (integration) ← depends on all above
         │
         ▼
Task 7 (build verification)
```
