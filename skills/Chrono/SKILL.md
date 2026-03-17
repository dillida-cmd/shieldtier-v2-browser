---
name: Chrono
description: Use when building the CEF browser shell — CefApp, CefClient, CefResponseFilter, CefDownloadHandler, CefRequestHandler, CefCookieManager, tab management, and navigation
---

# S1 — Chrono: CEF Shell Browser Engine Core

## Overview

Build the core CEF browser window with all Chromium-level handlers. This is the foundation that replaces Electron — it gives ShieldTier native streaming response interception, download lifecycle control, network policy enforcement, and per-tab session isolation.

## Dependencies

- **Requires:** S0 (foundation) complete — CMakeLists.txt, CEF SDK, shared types
- **Blocks:** S2 (ipc-bridge), S7 (capture uses CEF CDP)

## File Ownership

```
src/native/app/
  main.cpp              (platform entry point — macOS/Linux/Windows)
  app_handler.cpp/.h    (CefApp + CefBrowserProcessHandler)
  browser_handler.cpp/.h (CefClient implementation)
  renderer_app.cpp/.h   (CefRenderProcessHandler for sub-processes)
src/native/browser/
  session_manager.cpp/.h   (per-tab CefBrowser + CefRequestContext)
  response_filter.cpp/.h   (CefResponseFilter streaming interception)
  download_handler.cpp/.h  (CefDownloadHandler lifecycle)
  request_handler.cpp/.h   (CefRequestHandler network policy)
  cookie_manager.cpp/.h    (per-session CefCookieManager)
  navigation.cpp/.h        (back/forward/reload/URL bar)
```

## Exit Criteria

Browser opens, navigates to URLs, renders pages. Downloads are intercepted in-memory via CefResponseFilter with incremental SHA-256 hashing. Private IP ranges are blocked. Each tab has isolated cookies/sessions. Disk writes are suppressed for downloads.

---

## Architecture: Handler Chain

```
CefClient (ShieldTierClient)
  ├── GetLifeSpanHandler()    → OnAfterCreated, OnBeforeClose
  ├── GetRequestHandler()     → ShieldTierRequestHandler
  │     ├── OnBeforeBrowse()  → block javascript:/data:/private IPs
  │     ├── OnCertificateError() → allow (malware sites have bad certs)
  │     └── GetResourceRequestHandler() → ShieldTierResourceRequestHandler
  │           └── GetResourceResponseFilter() → DownloadCaptureFilter / StreamingHashFilter
  ├── GetDownloadHandler()    → ShieldTierDownloadHandler
  │     ├── OnBeforeDownload() → suppress disk write (don't call Continue)
  │     └── OnDownloadUpdated() → cancel if suppressed
  ├── GetDisplayHandler()     → OnTitleChange, OnAddressChange
  └── OnProcessMessageReceived() → forward to CefMessageRouter (S2 wires this)
```

## Key Design Decisions

### Response Interception Strategy

Two filter types based on Content-Length:

1. **DownloadCaptureFilter** (< 500MB): Accumulates all bytes in `std::vector<uint8_t>` + incremental SHA-256. On completion, passes the full buffer to the analysis engine.

2. **StreamingHashFilter** (>= 500MB or unknown): Only hashes incrementally, does not accumulate. Checks hash against bloom filter / threat intel after completion.

Download detection criteria (checked in GetResourceResponseFilter):
- `Content-Disposition: attachment`
- Binary MIME types (application/octet-stream, x-msdownload, x-executable, zip, rar, 7z, pdf)
- URL extension (.exe, .dll, .scr, .msi, .zip, .rar, .7z, .bat, .cmd, .ps1, .vbs, .js, .hta, .iso)

### Tab Isolation Model

Each tab gets its own `CefRequestContext` with a unique `cache_path` under `root_cache_path`. This gives complete isolation of:
- Cookies (separate CefCookieManager per context)
- localStorage / IndexedDB
- HTTP cache
- Service workers

For in-memory-only tabs (no disk persistence), set `cache_path` to empty string.

### CefSettings Configuration

```cpp
CefSettings settings;
settings.no_sandbox = true;
settings.log_severity = LOGSEVERITY_WARNING;
CefString(&settings.root_cache_path) = "/tmp/shieldtier/cache";
// browser_subprocess_path: set on macOS for helper executable
```

### Network Policy (CefRequestHandler)

Block:
- Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
- javascript: / vbscript: / data:text/html URLs
- WebRTC leaks via command-line flags:
  - `force-webrtc-ip-handling-policy=disable_non_proxied_udp`
  - `disable-features=WebRtcHideLocalIpsWithMdns`

Allow:
- All SSL certificate errors (log them — malware sites have bad certs)

### Platform Entry Points

- **macOS**: Requires separate helper executable for renderer/GPU sub-processes. Use `CefScopedLibraryLoader` in helper. Link `-framework Cocoa`.
- **Linux**: Single executable mode. `CefExecuteProcess` returns -1 for browser process, >= 0 for sub-processes.
- **Windows**: `wWinMain` entry point. Link `cef_sandbox.lib` if using sandbox.

### CefResponseFilter::Filter() Contract

```
Filter() called repeatedly with chunks of response body bytes.

Parameters:
  data_in          — input buffer (network bytes). NULL when data_in_size is 0.
  data_in_size     — bytes available in input buffer
  data_in_read     — [OUT] bytes consumed from input (set to data_in_size to consume all)
  data_out         — output buffer for pass-through data
  data_out_size    — capacity of output buffer
  data_out_written — [OUT] bytes written to output

Return values:
  RESPONSE_FILTER_NEED_MORE_DATA (0) — more chunks expected
  RESPONSE_FILTER_DONE (1)           — final chunk processed, filtering complete
  RESPONSE_FILTER_ERROR (2)          — abort the resource load

When data_in_size == 0: this is the completion signal. Finalize hash, deliver buffer.
```

### Download Suppression Pattern

CefResponseFilter receives bytes BEFORE CefDownloadHandler fires. By the time OnBeforeDownload is called, the filter already has the data. Suppress disk write by not calling `callback->Continue()` in OnBeforeDownload.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Not building libcef_dll_wrapper | `add_subdirectory("${CEF_ROOT}/libcef_dll")` in CMake |
| Not copying CEF resources to build dir | CEF needs icudtl.dat, v8_context_snapshot.bin, *.pak, locales/ at runtime |
| macOS: no helper executable | Renderer process crashes. Must build separate helper binary |
| Not forwarding OnProcessMessageReceived to message router | IPC from renderer silently fails |
| Not calling OnAfterCreated/OnBeforeClose on message router | Memory leaks, stale handlers |
| Setting same cache_path for multiple tabs | CEF locks cache dirs. Each tab needs unique path |
| root_cache_path not set when using per-tab cache_path | CEF requires all cache paths be children of root_cache_path |
| Calling CefShutdown without CefRunMessageLoop | Crashes. Must run message loop first |
