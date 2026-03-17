# Wave 4: End-to-End IPC Bridge — Design

**Goal:** Wire the React renderer UI to the native C++ backend so the app is fully functional — downloads are auto-analyzed, VM events stream in real-time, and navigation works.

**Architecture:** Custom scheme handler serves React build from disk. Response filter captures downloads and auto-triggers the analysis pipeline. Native→renderer push events via `CefExecuteJavaScript()` replace polling for real-time data. New IPC actions for VM control and navigation feedback.

---

## 1. Custom Scheme Handler — Serving the React UI

Register `shieldtier://` custom scheme via `CefSchemeHandlerFactory`.

```
shieldtier://app/           → dist/index.html
shieldtier://app/assets/... → dist/assets/...
shieldtier://app/fonts/...  → dist/fonts/...
```

**Files:**
- Create: `src/native/browser/scheme_handler.h` / `scheme_handler.cpp`
- Modify: `src/native/app/shieldtier_app.cpp` — register scheme + factory
- Modify: `src/native/app/shieldtier_app.h` — `OnRegisterCustomSchemes()` override

**Dev mode:** Environment variable `SHIELDTIER_DEV_URL` (e.g. `http://localhost:5173`) bypasses scheme handler, navigates to Vite dev server for hot reload.

**MIME map:** `.html`→`text/html`, `.js`→`application/javascript`, `.css`→`text/css`, `.woff2`→`font/woff2`, `.json`→`application/json`, `.svg`→`image/svg+xml`, `.png`→`image/png`.

---

## 2. Response Filter → Auto-Analysis Pipeline

Wire `GetResourceResponseFilter()` to detect downloads and auto-analyze.

**Detection criteria** (any match):
- `Content-Disposition: attachment`
- Binary MIME types (application/octet-stream, application/x-msdownload, etc.)
- Known dangerous extensions (.exe, .dll, .scr, .bat, .ps1, .vbs, etc.)

**Data flow:**
```
Response arrives with download indicators
  → RequestHandler::GetResourceResponseFilter() returns DownloadCaptureFilter
  → Filter accumulates bytes via Filter(), computes streaming SHA-256
  → Filter complete → store bytes in SessionManager keyed by SHA-256
  → Auto-call MessageHandler::handle_analyze_download(sha256)
  → jthread runs 7-engine analysis pipeline
  → Result stored → push to renderer via EventBridge
  → UI updates: TopBar verdict, FindingsPanel, IOCPanel, MITREPanel
```

**Files:**
- Modify: `src/native/browser/request_handler.cpp` — implement `GetResourceResponseFilter()`
- Modify: `src/native/browser/response_filter.cpp` — add completion callback
- Modify: `src/native/browser/session_manager.h/.cpp` — add captured file storage
- Modify: `src/native/ipc/message_handler.cpp` — auto-trigger from filter completion

---

## 3. Native→Renderer Push Events (EventBridge)

Replace polling with real-time push via `CefExecuteJavaScript()`.

**EventBridge class:**
```cpp
class EventBridge {
    void push_analysis_complete(sha256, result);
    void push_analysis_progress(sha256, engine, status);
    void push_vm_event(event);
    void push_vm_status(status);
    void push_vm_findings(findings);
    void push_vm_process_tree(tree);
    void push_vm_network_summary(summary);
    void push_download_detected(sha256, filename, size);
    void push_capture_update(capture_data);
    void push_navigation_state(can_back, can_forward, loading, url, title);
};
```

Each method calls:
```cpp
browser_->GetMainFrame()->ExecuteJavaScript(
    "window.__shieldtier_push('" + event + "'," + data.dump() + ")", "", 0);
```

**Renderer side** — `window.__shieldtier_push` dispatches to Zustand store:
```typescript
window.__shieldtier_push = (event: string, data: unknown) => {
  const store = useStore.getState();
  // switch on event type → call appropriate store setter
};
```

**Files:**
- Create: `src/native/ipc/event_bridge.h` / `event_bridge.cpp`
- Modify: `src/renderer/src/main.tsx` — register `window.__shieldtier_push`
- Modify: `src/renderer/src/store/index.ts` — add navigation state + new setters
- Modify: `src/native/app/shieldtier_client.cpp` — create EventBridge, pass to handlers

---

## 4. VM Control IPC

Add IPC actions for VM lifecycle control from the renderer.

**New actions in `ipc_protocol.h`:**
- `start_vm` — `{os: "alpine"|"reactos"|"windows"}` → boots QEMU
- `stop_vm` — `{}` → stops running VM
- `submit_sample_to_vm` — `{sha256: string}` → submits file to running VM

**VM event flow:**
```
User clicks START in VMControls
  → ipcCall('start_vm', {os: 'alpine'})
  → VmManager boots QEMU
  → EventBridge pushes vm_status('booting'), vm_status('running')
  → VM agent sends behavioral events
  → VmScoring scores events → EventBridge pushes vm_event, vm_findings
  → UI updates: VMTerminal, SandboxPanel, ProcessPanel, MITREPanel
```

**Files:**
- Modify: `src/native/ipc/ipc_protocol.h` — add 3 action constants
- Modify: `src/native/ipc/message_handler.h/.cpp` — add 3 handlers
- Modify: `src/renderer/src/components/vm/VMControls.tsx` — wire buttons to IPC
- Modify: `src/renderer/src/ipc/types.ts` — add new action types

---

## 5. Navigation & Tab Feedback

Wire browser navigation state back to the renderer.

**Navigation state push** — `RequestHandler::OnLoadingStateChange()`:
```cpp
event_bridge_->push_navigation_state(can_go_back, can_go_forward, is_loading, url);
```

**New IPC actions:**
- `nav_back` — calls `browser->GoBack()`
- `nav_forward` — calls `browser->GoForward()`
- `nav_reload` — calls `browser->Reload()`
- `nav_stop` — calls `browser->StopLoad()`

**Store additions:**
- `navCanGoBack`, `navCanGoForward`, `navIsLoading`, `navCurrentUrl`, `navTitle`

**Files:**
- Modify: `src/native/browser/request_handler.cpp` — `OnLoadingStateChange()` push
- Modify: `src/native/app/shieldtier_client.cpp` — `OnTitleChange()` push
- Modify: `src/native/ipc/ipc_protocol.h` — add nav action constants
- Modify: `src/native/ipc/message_handler.cpp` — add nav handlers
- Modify: `src/renderer/src/store/index.ts` — add nav state
- Modify: `src/renderer/src/components/workspace/BrowserZone.tsx` — wire buttons + URL sync

---

## Summary

| Section | New Files | Modified Files |
|---------|-----------|---------------|
| 1. Scheme Handler | `scheme_handler.h/.cpp` | `shieldtier_app.h/.cpp` |
| 2. Response Filter | — | `request_handler.cpp`, `response_filter.cpp`, `session_manager.h/.cpp`, `message_handler.cpp` |
| 3. Event Bridge | `event_bridge.h/.cpp` | `main.tsx`, `store/index.ts`, `shieldtier_client.cpp` |
| 4. VM Control | — | `ipc_protocol.h`, `message_handler.h/.cpp`, `VMControls.tsx`, `types.ts` |
| 5. Navigation | — | `request_handler.cpp`, `shieldtier_client.cpp`, `ipc_protocol.h`, `message_handler.cpp`, `BrowserZone.tsx`, `store/index.ts` |

**New files:** 4 (scheme_handler.h/.cpp, event_bridge.h/.cpp)
**Modified files:** ~15 across native + renderer
