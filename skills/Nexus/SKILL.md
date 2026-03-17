---
name: Nexus
description: Use when building the native-to-renderer IPC bridge — CefMessageRouter, JSON protocol, window.cefQuery wrapper, Vite build config, and React bootstrap for CEF
---

# S2 — Nexus: IPC Bridge Native ↔ Renderer Communication

## Overview

Bridge between CEF C++ native code and the React renderer UI. Uses CefMessageRouter for bidirectional JSON messaging. The renderer loads from `dist/renderer/index.html` via Vite build.

## Dependencies

- **Requires:** S1 (cef-shell) complete — CefClient must forward OnProcessMessageReceived
- **Blocks:** All analysis agents need IPC to send results to UI

## File Ownership

```
src/native/ipc/
  handler.cpp/.h     (CefMessageRouterBrowserSideHandler implementation)
  protocol.h         (all IPC message types as JSON schemas)
src/renderer/
  ipc/cef-bridge.ts  (window.cefQuery wrapper with typed messages)
  ipc/types.ts       (TypeScript IPC message type definitions)
vite.config.ts       (Vite build → dist/renderer/)
```

## Exit Criteria

React UI sends typed IPC request → native handler processes → native responds with JSON → UI renders result. Round-trip under 5ms for local operations.

---

## Architecture

```
React UI (renderer process)
  │
  window.cefQuery({ request: JSON, onSuccess, onFailure })
  │
  ▼
CefMessageRouterRendererSide (in renderer process, auto-registered)
  │
  CefProcessMessage (IPC between processes)
  │
  ▼
CefMessageRouterBrowserSide (in browser process)
  │
  ShieldTierQueryHandler::OnQuery(browser, frame, query_id, request, ...)
  │
  Parse JSON → dispatch to native handler → callback->Success(response_json)
```

## CefMessageRouter Setup

### Browser Process (app_handler.cpp — S1 wires this)

```cpp
#include "include/cef_message_router.h"
#include "include/wrapper/cef_message_router.h"

// In CefBrowserProcessHandler::OnContextInitialized():
CefMessageRouterConfig config;
config.js_query_function = "cefQuery";       // window.cefQuery()
config.js_cancel_function = "cefQueryCancel"; // window.cefQueryCancel()

CefRefPtr<CefMessageRouterBrowserSide> message_router_ =
    CefMessageRouterBrowserSide::Create(config);

// Register our handler
message_router_->AddHandler(new ShieldTierQueryHandler(), true);
```

### Wiring into CefClient (browser_handler.cpp — S1 provides hooks)

```cpp
// OnAfterCreated — register browser with router
void ShieldTierClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
    message_router_->OnAfterCreated(browser);
}

// OnBeforeClose — deregister browser
void ShieldTierClient::OnBeforeClose(CefRefPtr<CefBrowser> browser) {
    message_router_->OnBeforeClose(browser);
}

// OnProcessMessageReceived — forward to router
bool ShieldTierClient::OnProcessMessageReceived(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    CefProcessId source_process,
    CefRefPtr<CefProcessMessage> message) {
    return message_router_->OnProcessMessageReceived(
        browser, frame, source_process, message);
}

// OnBeforeBrowse — forward to router
bool ShieldTierRequestHandler::OnBeforeBrowse(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    CefRefPtr<CefRequest> request,
    bool user_gesture,
    bool is_redirect) {
    message_router_->OnBeforeBrowse(browser, frame);
    return false; // allow navigation
}
```

### Renderer Process (renderer_app.cpp)

```cpp
#include "include/wrapper/cef_message_router.h"

class ShieldTierRendererApp : public CefApp, public CefRenderProcessHandler {
    CefRefPtr<CefMessageRouterRendererSide> message_router_;

    void OnContextCreated(CefRefPtr<CefBrowser> browser,
                          CefRefPtr<CefFrame> frame,
                          CefRefPtr<CefV8Context> context) override {
        CefMessageRouterConfig config;
        config.js_query_function = "cefQuery";
        config.js_cancel_function = "cefQueryCancel";
        message_router_ = CefMessageRouterRendererSide::Create(config);
        message_router_->OnContextCreated(browser, frame, context);
    }

    void OnContextReleased(CefRefPtr<CefBrowser> browser,
                           CefRefPtr<CefFrame> frame,
                           CefRefPtr<CefV8Context> context) override {
        message_router_->OnContextReleased(browser, frame, context);
    }

    bool OnProcessMessageReceived(CefRefPtr<CefBrowser> browser,
                                  CefRefPtr<CefFrame> frame,
                                  CefProcessId source_process,
                                  CefRefPtr<CefProcessMessage> message) override {
        return message_router_->OnProcessMessageReceived(
            browser, frame, source_process, message);
    }
};
```

## Query Handler (handler.cpp)

```cpp
#include "include/wrapper/cef_message_router.h"
#include "ipc/protocol.h"
#include <nlohmann/json.hpp>

class ShieldTierQueryHandler : public CefMessageRouterBrowserSide::Handler {
public:
    bool OnQuery(CefRefPtr<CefBrowser> browser,
                 CefRefPtr<CefFrame> frame,
                 int64_t query_id,
                 const CefString& request,
                 bool persistent,
                 CefRefPtr<Callback> callback) override {

        auto msg = nlohmann::json::parse(request.ToString());
        std::string type = msg["type"];

        if (type == "analyze_file") {
            // Dispatch to analysis engine (async — use persistent callback)
            auto file_id = msg["payload"]["file_id"].get<std::string>();
            // ... start analysis, store callback for later ...
            // callback->Success(result_json) when done
            return true;
        }

        if (type == "get_tab_info") {
            auto tab_id = msg["payload"]["tab_id"].get<int>();
            nlohmann::json response = {
                {"type", "tab_info"},
                {"payload", {{"id", tab_id}, {"url", "..."}, {"title", "..."}}}
            };
            callback->Success(response.dump());
            return true;
        }

        if (type == "navigate") {
            auto url = msg["payload"]["url"].get<std::string>();
            browser->GetMainFrame()->LoadURL(url);
            callback->Success(R"({"type":"navigate_ok"})");
            return true;
        }

        return false; // not handled
    }

    void OnQueryCanceled(CefRefPtr<CefBrowser> browser,
                         CefRefPtr<CefFrame> frame,
                         int64_t query_id) override {
        // Clean up any pending async operations for this query
    }
};
```

## IPC Protocol (protocol.h)

```cpp
#pragma once
#include <string>

namespace shieldtier::ipc {

// Message envelope: { "type": "<msg_type>", "payload": { ... } }
// Response envelope: { "type": "<msg_type>_result", "payload": { ... } }
// Error envelope: { "type": "error", "payload": { "code": "...", "message": "..." } }

// --- Navigation ---
// navigate:          { url: string }
// navigate_back:     {}
// navigate_forward:  {}
// reload:            {}

// --- Tab Management ---
// create_tab:        { url?: string, isolated?: bool }
// close_tab:         { tab_id: int }
// get_tab_info:      { tab_id: int }
// list_tabs:         {}

// --- Analysis ---
// analyze_file:      { file_id: string, engines: string[] }
// get_analysis:      { file_id: string }
// cancel_analysis:   { file_id: string }

// --- Downloads ---
// list_downloads:    {}
// get_download:      { download_id: string }

// --- Config ---
// get_config:        { key: string }
// set_config:        { key: string, value: any }

// --- Enrichment ---
// enrich_hash:       { hash: string, providers: string[] }

// --- Events (persistent queries — native pushes to renderer) ---
// subscribe:         { event: string }   → persistent callback
// Events: download_progress, analysis_progress, analysis_complete, tab_updated

} // namespace shieldtier::ipc
```

## Renderer Side (TypeScript)

### ipc/cef-bridge.ts

```typescript
type IpcMessage = {
  type: string;
  payload: Record<string, unknown>;
};

export function sendIpc<T>(message: IpcMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    window.cefQuery({
      request: JSON.stringify(message),
      onSuccess: (response: string) => {
        resolve(JSON.parse(response) as T);
      },
      onFailure: (errorCode: number, errorMessage: string) => {
        reject(new Error(`IPC error ${errorCode}: ${errorMessage}`));
      },
    });
  });
}

// Persistent subscription for events (native pushes updates)
export function subscribe(
  event: string,
  callback: (data: unknown) => void
): () => void {
  const queryId = window.cefQuery({
    request: JSON.stringify({ type: "subscribe", payload: { event } }),
    persistent: true,
    onSuccess: (response: string) => {
      callback(JSON.parse(response));
    },
    onFailure: () => {},
  });

  return () => window.cefQueryCancel(queryId);
}
```

### Window type declaration

```typescript
declare global {
  interface Window {
    cefQuery(params: {
      request: string;
      persistent?: boolean;
      onSuccess: (response: string) => void;
      onFailure: (errorCode: number, errorMessage: string) => void;
    }): number;
    cefQueryCancel(queryId: number): void;
  }
}
```

## Vite Build Config

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  root: 'src/renderer',
  build: {
    outDir: '../../dist/renderer',
    emptyDirOnBuild: true,
  },
  base: './',  // relative paths for file:// loading in CEF
});
```

CEF loads the built renderer:

```cpp
// In main.cpp after browser creation:
std::string renderer_path = GetAppDir() + "/dist/renderer/index.html";
browser->GetMainFrame()->LoadURL("file://" + renderer_path);
```

## Persistent Queries (Event Push)

For real-time updates (download progress, analysis results), use persistent queries:

```cpp
// Native side — store persistent callback
struct PersistentSubscription {
    int64_t query_id;
    CefRefPtr<CefMessageRouterBrowserSide::Handler::Callback> callback;
    std::string event_type;
};

// Push event to renderer:
void push_event(const std::string& event_type, const nlohmann::json& data) {
    for (auto& sub : subscriptions_) {
        if (sub.event_type == event_type) {
            sub.callback->Success(data.dump());
            // persistent=true means callback stays valid for more calls
        }
    }
}
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Not forwarding OnProcessMessageReceived to router | IPC silently fails — no error, no callback |
| Not calling OnAfterCreated/OnBeforeClose on router | Memory leaks, stale handlers |
| Not calling OnBeforeBrowse on router | Pending queries leak on navigation |
| Using `cefQuery` before context created | Wrap in `DOMContentLoaded` or React `useEffect` |
| Not setting `base: './'` in Vite | Asset paths break when loaded via `file://` |
| Forgetting renderer_app for renderer process | `cefQuery` not injected — undefined in JS |
| Blocking OnQuery with sync work | Freezes browser process UI — use async + persistent |
| Not matching js_query_function config in both processes | Browser and renderer must use same config string |
