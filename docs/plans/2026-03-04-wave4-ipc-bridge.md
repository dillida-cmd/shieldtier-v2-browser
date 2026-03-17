# Wave 4: End-to-End IPC Bridge — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the React renderer UI to the native C++ backend end-to-end — custom scheme serves UI, response filter auto-analyzes downloads, push events stream VM/analysis data in real-time, and navigation controls work.

**Architecture:** Custom `shieldtier://` scheme handler serves the React build from disk. `EventBridge` class pushes data from native to renderer via `CefExecuteJavaScript`. Response filter captures downloads and auto-triggers the analysis pipeline. New IPC actions control VM lifecycle and browser navigation.

**Tech Stack:** CEF 145, C++20, React 19, Zustand, TypeScript 5.7

---

### Task 1: Custom Scheme Handler

Serve the React renderer build via `shieldtier://app/` protocol. CEF navigates to this URL on startup instead of `about:blank`.

**Files:**
- Create: `src/native/browser/scheme_handler.h`
- Create: `src/native/browser/scheme_handler.cpp`
- Modify: `src/native/app/shieldtier_app.h`
- Modify: `src/native/app/shieldtier_app.cpp`
- Modify: `src/native/CMakeLists.txt`

**Step 1: Create scheme_handler.h**

```cpp
#pragma once

#include <string>
#include <vector>

#include "include/cef_resource_handler.h"
#include "include/cef_scheme.h"

namespace shieldtier {

class SchemeHandler : public CefResourceHandler {
public:
    explicit SchemeHandler(const std::string& root_dir);

    bool Open(CefRefPtr<CefRequest> request, bool& handle_request,
              CefRefPtr<CefCallback> callback) override;

    void GetResponseHeaders(CefRefPtr<CefResponse> response,
                            int64_t& response_length,
                            CefString& redirect_url) override;

    bool Read(void* data_out, int bytes_to_read, int& bytes_read,
              CefRefPtr<CefResourceReadCallback> callback) override;

    void Cancel() override;

private:
    static std::string get_mime_type(const std::string& extension);

    std::string root_dir_;
    std::vector<uint8_t> data_;
    size_t offset_ = 0;
    std::string mime_type_ = "text/html";
    int status_code_ = 200;

    IMPLEMENT_REFCOUNTING(SchemeHandler);
    DISALLOW_COPY_AND_ASSIGN(SchemeHandler);
};

class SchemeHandlerFactory : public CefSchemeHandlerFactory {
public:
    explicit SchemeHandlerFactory(const std::string& root_dir);

    CefRefPtr<CefResourceHandler> Create(
        CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
        const CefString& scheme_name,
        CefRefPtr<CefRequest> request) override;

private:
    std::string root_dir_;

    IMPLEMENT_REFCOUNTING(SchemeHandlerFactory);
    DISALLOW_COPY_AND_ASSIGN(SchemeHandlerFactory);
};

}  // namespace shieldtier
```

**Step 2: Create scheme_handler.cpp**

```cpp
#include "browser/scheme_handler.h"

#include "include/cef_parser.h"

#include <filesystem>
#include <fstream>

namespace shieldtier {

namespace fs = std::filesystem;

SchemeHandler::SchemeHandler(const std::string& root_dir) : root_dir_(root_dir) {}

bool SchemeHandler::Open(CefRefPtr<CefRequest> request, bool& handle_request,
                         CefRefPtr<CefCallback> /*callback*/) {
    handle_request = true;

    CefURLParts url_parts;
    if (!CefParseURL(request->GetURL(), url_parts)) {
        status_code_ = 400;
        return true;
    }

    std::string path = CefString(&url_parts.path).ToString();
    if (path.empty() || path == "/") {
        path = "/index.html";
    }

    // Prevent directory traversal
    if (path.find("..") != std::string::npos) {
        status_code_ = 403;
        return true;
    }

    fs::path file_path = fs::path(root_dir_) / path.substr(1);

    if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
        // SPA fallback: serve index.html for unrecognized paths
        file_path = fs::path(root_dir_) / "index.html";
        if (!fs::exists(file_path)) {
            status_code_ = 404;
            return true;
        }
    }

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        status_code_ = 500;
        return true;
    }

    auto size = file.tellg();
    file.seekg(0);
    data_.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(data_.data()), size);

    mime_type_ = get_mime_type(file_path.extension().string());
    status_code_ = 200;
    return true;
}

void SchemeHandler::GetResponseHeaders(CefRefPtr<CefResponse> response,
                                       int64_t& response_length,
                                       CefString& /*redirect_url*/) {
    response->SetStatus(status_code_);
    response->SetMimeType(mime_type_);

    if (status_code_ == 200) {
        response->SetHeaderByName("Access-Control-Allow-Origin", "*", true);
        response_length = static_cast<int64_t>(data_.size());
    } else {
        response_length = 0;
    }
}

bool SchemeHandler::Read(void* data_out, int bytes_to_read, int& bytes_read,
                         CefRefPtr<CefResourceReadCallback> /*callback*/) {
    if (offset_ >= data_.size()) {
        bytes_read = 0;
        return false;
    }

    size_t remaining = data_.size() - offset_;
    size_t to_copy = std::min(static_cast<size_t>(bytes_to_read), remaining);
    memcpy(data_out, data_.data() + offset_, to_copy);
    offset_ += to_copy;
    bytes_read = static_cast<int>(to_copy);
    return true;
}

void SchemeHandler::Cancel() {
    data_.clear();
    offset_ = 0;
}

std::string SchemeHandler::get_mime_type(const std::string& ext) {
    if (ext == ".html") return "text/html";
    if (ext == ".js")   return "application/javascript";
    if (ext == ".css")  return "text/css";
    if (ext == ".json") return "application/json";
    if (ext == ".svg")  return "image/svg+xml";
    if (ext == ".png")  return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".woff")  return "font/woff";
    if (ext == ".woff2") return "font/woff2";
    if (ext == ".ttf")   return "font/ttf";
    if (ext == ".ico")   return "image/x-icon";
    if (ext == ".map")   return "application/json";
    return "application/octet-stream";
}

// Factory

SchemeHandlerFactory::SchemeHandlerFactory(const std::string& root_dir)
    : root_dir_(root_dir) {}

CefRefPtr<CefResourceHandler> SchemeHandlerFactory::Create(
    CefRefPtr<CefBrowser> /*browser*/, CefRefPtr<CefFrame> /*frame*/,
    const CefString& /*scheme_name*/, CefRefPtr<CefRequest> /*request*/) {
    return new SchemeHandler(root_dir_);
}

}  // namespace shieldtier
```

**Step 3: Modify shieldtier_app.h — add OnRegisterCustomSchemes**

Add this method after `OnContextInitialized()` on line 14:

```cpp
    void OnRegisterCustomSchemes(
        CefRawPtr<CefSchemeRegistrar> registrar) override;
```

**Step 4: Modify shieldtier_app.cpp — register scheme and navigate to it**

Replace the entire file with:

```cpp
#include "app/shieldtier_app.h"
#include "app/shieldtier_client.h"
#include "browser/scheme_handler.h"

#include "include/cef_browser.h"
#include "include/cef_command_line.h"
#include "include/cef_scheme.h"

#include <cstdlib>
#include <filesystem>

void ShieldTierApp::OnRegisterCustomSchemes(
        CefRawPtr<CefSchemeRegistrar> registrar) {
    registrar->AddCustomScheme(
        "shieldtier",
        CEF_SCHEME_IS_STANDARD | CEF_SCHEME_IS_SECURE |
        CEF_SCHEME_IS_CORS_ENABLED | CEF_SCHEME_IS_FETCH_ENABLED);
}

void ShieldTierApp::OnContextInitialized() {
    const std::string root_cache_path = "/tmp/shieldtier/cache";

    // Register scheme handler factory for serving React UI
    const char* renderer_path = std::getenv("SHIELDTIER_RENDERER_PATH");
    std::string renderer_dist = renderer_path
        ? std::string(renderer_path)
        : (std::filesystem::current_path() / "src" / "renderer" / "dist").string();

    CefRegisterSchemeHandlerFactory(
        "shieldtier", "app",
        new shieldtier::SchemeHandlerFactory(renderer_dist));

    CefRefPtr<ShieldTierClient> client(
        new ShieldTierClient(root_cache_path));

    // Dev mode: env var overrides to Vite dev server for hot reload
    const char* dev_url = std::getenv("SHIELDTIER_DEV_URL");
    std::string initial_url = dev_url ? std::string(dev_url) : "shieldtier://app/";

    client->session_manager()->create_tab(initial_url, true, client);
}
```

**Step 5: Add scheme_handler.cpp to CMakeLists.txt**

In `src/native/CMakeLists.txt`, add after line 12 (`browser/navigation.cpp`):

```
    browser/scheme_handler.cpp
```

**Step 6: Commit**

```bash
git add src/native/browser/scheme_handler.h src/native/browser/scheme_handler.cpp \
        src/native/app/shieldtier_app.h src/native/app/shieldtier_app.cpp \
        src/native/CMakeLists.txt
git commit -m "feat(wave4): add custom scheme handler — serve React UI via shieldtier://app/"
```

---

### Task 2: Event Bridge (Native Side)

Create the `EventBridge` class that pushes data from native C++ to the renderer via `CefExecuteJavaScript()`.

**Files:**
- Create: `src/native/ipc/event_bridge.h`
- Create: `src/native/ipc/event_bridge.cpp`
- Modify: `src/native/CMakeLists.txt`

**Step 1: Create event_bridge.h**

```cpp
#pragma once

#include <mutex>
#include <string>

#include "include/cef_browser.h"
#include "include/cef_task.h"

#include "common/json.h"

namespace shieldtier {

class EventBridge {
public:
    void set_browser(CefRefPtr<CefBrowser> browser);
    void clear_browser();

    void push_analysis_complete(const std::string& sha256, const json& result);
    void push_analysis_progress(const std::string& sha256,
                                const std::string& engine,
                                const std::string& status);
    void push_download_detected(const std::string& sha256,
                                const std::string& filename, size_t size);

    void push_vm_event(const json& event);
    void push_vm_status(const std::string& status);
    void push_vm_findings(const json& findings);
    void push_vm_process_tree(const json& tree);
    void push_vm_network_summary(const json& summary);

    void push_capture_update(const json& data);
    void push_navigation_state(bool can_back, bool can_forward, bool loading,
                               const std::string& url,
                               const std::string& title);

private:
    void push(const std::string& event, const json& data);

    CefRefPtr<CefBrowser> browser_;
    std::mutex mutex_;
};

}  // namespace shieldtier
```

**Step 2: Create event_bridge.cpp**

```cpp
#include "ipc/event_bridge.h"

namespace shieldtier {

namespace {

// CefTask wrapper for posting JavaScript execution to the UI thread.
class JsExecTask : public CefTask {
public:
    JsExecTask(CefRefPtr<CefBrowser> browser, std::string code)
        : browser_(browser), code_(std::move(code)) {}

    void Execute() override {
        auto frame = browser_->GetMainFrame();
        if (frame) {
            frame->ExecuteJavaScript(code_, "", 0);
        }
    }

private:
    CefRefPtr<CefBrowser> browser_;
    std::string code_;
    IMPLEMENT_REFCOUNTING(JsExecTask);
};

}  // namespace

void EventBridge::set_browser(CefRefPtr<CefBrowser> browser) {
    std::lock_guard<std::mutex> lock(mutex_);
    browser_ = browser;
}

void EventBridge::clear_browser() {
    std::lock_guard<std::mutex> lock(mutex_);
    browser_ = nullptr;
}

void EventBridge::push(const std::string& event, const json& data) {
    CefRefPtr<CefBrowser> browser;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        browser = browser_;
    }
    if (!browser) return;

    std::string js = "window.__shieldtier_push&&window.__shieldtier_push('"
        + event + "'," + data.dump() + ")";

    if (CefCurrentlyOn(TID_UI)) {
        auto frame = browser->GetMainFrame();
        if (frame) frame->ExecuteJavaScript(js, "", 0);
    } else {
        CefPostTask(TID_UI, new JsExecTask(browser, std::move(js)));
    }
}

void EventBridge::push_analysis_complete(const std::string& sha256,
                                          const json& result) {
    push("analysis_complete", {{"sha256", sha256}, {"result", result}});
}

void EventBridge::push_analysis_progress(const std::string& sha256,
                                          const std::string& engine,
                                          const std::string& status) {
    push("analysis_progress",
         {{"sha256", sha256}, {"engine", engine}, {"status", status}});
}

void EventBridge::push_download_detected(const std::string& sha256,
                                          const std::string& filename,
                                          size_t size) {
    push("download_detected",
         {{"sha256", sha256}, {"filename", filename}, {"size", size}});
}

void EventBridge::push_vm_event(const json& event) {
    push("vm_event", event);
}

void EventBridge::push_vm_status(const std::string& status) {
    push("vm_status", {{"status", status}});
}

void EventBridge::push_vm_findings(const json& findings) {
    push("vm_findings", findings);
}

void EventBridge::push_vm_process_tree(const json& tree) {
    push("vm_process_tree", tree);
}

void EventBridge::push_vm_network_summary(const json& summary) {
    push("vm_network_summary", summary);
}

void EventBridge::push_capture_update(const json& data) {
    push("capture_update", data);
}

void EventBridge::push_navigation_state(bool can_back, bool can_forward,
                                         bool loading,
                                         const std::string& url,
                                         const std::string& title) {
    push("navigation_state", {
        {"can_back", can_back},
        {"can_forward", can_forward},
        {"loading", loading},
        {"url", url},
        {"title", title},
    });
}

}  // namespace shieldtier
```

**Step 3: Add event_bridge.cpp to CMakeLists.txt**

In `src/native/CMakeLists.txt`, add after `ipc/message_handler.cpp` (line 13):

```
    ipc/event_bridge.cpp
```

**Step 4: Commit**

```bash
git add src/native/ipc/event_bridge.h src/native/ipc/event_bridge.cpp \
        src/native/CMakeLists.txt
git commit -m "feat(wave4): add EventBridge — push events from native to renderer via JS"
```

---

### Task 3: Wire EventBridge into ShieldTierClient and MessageHandler

Connect the EventBridge to the client lifecycle (set/clear browser) and give MessageHandler access to push analysis results.

**Files:**
- Modify: `src/native/app/shieldtier_client.h`
- Modify: `src/native/app/shieldtier_client.cpp`
- Modify: `src/native/ipc/message_handler.h`
- Modify: `src/native/ipc/message_handler.cpp`

**Step 1: Modify shieldtier_client.h — add EventBridge member and CefLoadHandler**

Add include after line 14:

```cpp
#include "ipc/event_bridge.h"
```

Change class declaration (line 16-18) to also inherit CefLoadHandler:

```cpp
class ShieldTierClient : public CefClient,
                         public CefLifeSpanHandler,
                         public CefDisplayHandler,
                         public CefLoadHandler {
```

Add after `GetDownloadHandler()` (after line 36):

```cpp
    CefRefPtr<CefLoadHandler> GetLoadHandler() override {
        return this;
    }
```

Add after `OnTitleChange` declaration (after line 45):

```cpp
    // CefLoadHandler
    void OnLoadingStateChange(CefRefPtr<CefBrowser> browser,
                              bool is_loading, bool can_go_back,
                              bool can_go_forward) override;
```

Add after `session_manager()` accessor (after line 55):

```cpp
    shieldtier::EventBridge* event_bridge() {
        return event_bridge_.get();
    }
```

Add to private members (after line 62):

```cpp
    std::unique_ptr<shieldtier::EventBridge> event_bridge_;
```

**Step 2: Modify shieldtier_client.cpp — create EventBridge, wire lifecycle**

Add to constructor, after `request_handler_->set_message_router(message_router_);` (line 15):

```cpp
    event_bridge_ = std::make_unique<shieldtier::EventBridge>();
    message_handler_->set_event_bridge(event_bridge_.get());
    request_handler_->set_event_bridge(event_bridge_.get());
```

Add to `OnAfterCreated` after line 21:

```cpp
    event_bridge_->set_browser(browser);
```

Add to `OnBeforeClose` before `if (browser_ && browser_->IsSame(browser))` (before line 32):

```cpp
    event_bridge_->clear_browser();
```

Replace `OnTitleChange` (lines 41-44) with:

```cpp
void ShieldTierClient::OnTitleChange(CefRefPtr<CefBrowser> /*browser*/,
                                     const CefString& title) {
    // Push title to renderer. Full nav state is pushed from OnLoadingStateChange.
    // Title arrives asynchronously so we push it separately.
}
```

Add `OnLoadingStateChange` implementation after `OnTitleChange`:

```cpp
void ShieldTierClient::OnLoadingStateChange(CefRefPtr<CefBrowser> browser,
                                             bool is_loading, bool can_go_back,
                                             bool can_go_forward) {
    std::string url;
    std::string title;
    auto frame = browser->GetMainFrame();
    if (frame) {
        url = frame->GetURL().ToString();
    }
    event_bridge_->push_navigation_state(
        can_go_back, can_go_forward, is_loading, url, title);
}
```

**Step 3: Modify message_handler.h — add EventBridge pointer and set_event_bridge**

Add include after line 12:

```cpp
#include "ipc/event_bridge.h"
```

Add public method after `OnQueryCanceled` (after line 43):

```cpp
    void set_event_bridge(EventBridge* bridge) { event_bridge_ = bridge; }
    void auto_analyze(const std::string& sha256);
```

Add private member after `SessionManager* session_manager_;` (line 59):

```cpp
    EventBridge* event_bridge_ = nullptr;
```

**Step 4: Modify message_handler.cpp — push analysis results via EventBridge**

Add `auto_analyze` method (public wrapper that reuses the analysis pipeline). Add after the `handle_get_capture` method, before the closing `}  // namespace`:

```cpp
void MessageHandler::auto_analyze(const std::string& sha256) {
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        auto it = analysis_results_.find(sha256);
        if (it != analysis_results_.end()) {
            std::string status = it->second.value("status", "");
            if (status == "pending" || status == "complete") return;
        }
        analysis_results_[sha256] = {{"status", "pending"}};
    }

    auto* sm = session_manager_;
    auto* yara = yara_engine_.get();
    auto* fa = file_analyzer_.get();
    auto* em = enrichment_manager_.get();
    auto* sc = scoring_engine_.get();
    auto* sandbox = sandbox_engine_.get();
    auto* advanced = advanced_engine_.get();
    auto* email = email_analyzer_.get();
    auto* content = content_analyzer_.get();
    auto* log_mgr = log_manager_.get();
    auto* results_map = &analysis_results_;
    auto* mtx = &results_mutex_;
    auto* bridge = event_bridge_;

    std::jthread thread([sha256, sm, yara, fa, em, sc, sandbox, advanced,
                         email, content, log_mgr, results_map, mtx, bridge]
                        (std::stop_token stop) {
        auto file_opt = sm->get_captured_download(sha256);
        if (!file_opt.has_value()) {
            json err = {{"status", "error"}, {"error", "download_not_found"}};
            std::lock_guard<std::mutex> lock(*mtx);
            (*results_map)[sha256] = err;
            if (bridge) bridge->push_analysis_complete(sha256, err);
            return;
        }

        FileBuffer file = std::move(file_opt.value());
        std::vector<AnalysisEngineResult> engine_results;

        if (stop.stop_requested()) return;
        auto yr = yara->scan(file);
        if (yr.ok()) engine_results.push_back(std::move(yr.value()));

        if (stop.stop_requested()) return;
        auto fr = fa->analyze(file);
        if (fr.ok()) engine_results.push_back(std::move(fr.value()));

        if (stop.stop_requested()) return;
        auto sr = sandbox->analyze(file);
        if (sr.ok()) engine_results.push_back(std::move(sr.value()));

        if (stop.stop_requested()) return;
        auto ar = advanced->analyze(file);
        if (ar.ok()) engine_results.push_back(std::move(ar.value()));

        if (stop.stop_requested()) return;
        auto er = email->analyze(file);
        if (er.ok()) engine_results.push_back(std::move(er.value()));

        if (stop.stop_requested()) return;
        auto cr = content->analyze(file);
        if (cr.ok()) engine_results.push_back(std::move(cr.value()));

        if (stop.stop_requested()) return;
        auto lr = log_mgr->analyze(file);
        if (lr.ok()) engine_results.push_back(std::move(lr.value()));

        if (stop.stop_requested()) return;
        std::string md5 = FileAnalyzer::compute_md5(file.ptr(), file.size());
        auto enr = em->enrich_by_hash(sha256, md5);
        if (enr.ok()) engine_results.push_back(std::move(enr.value()));

        auto verdict_result = sc->score(engine_results);

        json output;
        if (verdict_result.ok()) {
            output = {{"status", "complete"}, {"verdict", verdict_result.value()}};
        } else {
            output = {{"status", "error"}, {"error", verdict_result.error().message}};
        }

        {
            std::lock_guard<std::mutex> lock(*mtx);
            (*results_map)[sha256] = output;
        }

        if (bridge) bridge->push_analysis_complete(sha256, output);
    });

    std::lock_guard<std::mutex> lock(threads_mutex_);
    analysis_threads_.push_back(std::move(thread));
}
```

**Step 5: Commit**

```bash
git add src/native/app/shieldtier_client.h src/native/app/shieldtier_client.cpp \
        src/native/ipc/message_handler.h src/native/ipc/message_handler.cpp
git commit -m "feat(wave4): wire EventBridge into client lifecycle and message handler"
```

---

### Task 4: Renderer Push Handler and Store Updates

Register `window.__shieldtier_push` in the renderer and add navigation + download state to the Zustand store.

**Files:**
- Modify: `src/renderer/src/main.tsx`
- Modify: `src/renderer/src/store/index.ts`
- Modify: `src/renderer/src/ipc/types.ts`

**Step 1: Modify ipc/types.ts — add new IPC actions and DownloadInfo type**

Add to the `IpcAction` union (after `'get_capture'` on line 13):

```typescript
  | 'start_vm'
  | 'stop_vm'
  | 'submit_sample_to_vm'
  | 'nav_back'
  | 'nav_forward'
  | 'nav_reload'
  | 'nav_stop';
```

Add after the `NetworkSummary` interface (after line 86):

```typescript
export interface DownloadInfo {
  sha256: string;
  filename: string;
  size: number;
}
```

**Step 2: Modify store/index.ts — add navigation and download state**

Add `DownloadInfo` to the imports from `'../ipc/types'` (line 2-10):

```typescript
import type {
  AnalysisResult,
  CaptureData,
  DownloadInfo,
  VmStatus,
  VmEvent,
  Finding,
  ProcessNode,
  NetworkSummary,
} from '../ipc/types';
```

Add to `ShieldTierState` interface, after `vmNetworkSummary` (before the setters):

```typescript
  navCanGoBack: boolean;
  navCanGoForward: boolean;
  navIsLoading: boolean;
  navCurrentUrl: string;
  navTitle: string;

  currentDownload: DownloadInfo | null;
```

Add setters to the interface (after `setVmNetworkSummary`):

```typescript
  setNavState: (state: { can_back: boolean; can_forward: boolean; loading: boolean; url: string; title: string }) => void;
  setCurrentDownload: (info: DownloadInfo | null) => void;
  setCurrentSha256: (sha256: string) => void;
```

Add default values to the store (after `vmNetworkSummary: null,`):

```typescript
  navCanGoBack: false,
  navCanGoForward: false,
  navIsLoading: false,
  navCurrentUrl: '',
  navTitle: '',

  currentDownload: null,
```

Add setter implementations (after `setVmNetworkSummary`):

```typescript
  setNavState: (state) => set({
    navCanGoBack: state.can_back,
    navCanGoForward: state.can_forward,
    navIsLoading: state.loading,
    navCurrentUrl: state.url,
    navTitle: state.title,
  }),
  setCurrentDownload: (currentDownload) => set({ currentDownload }),
  setCurrentSha256: (sha256) => set({
    currentSha256: sha256,
    analysisStatus: 'pending',
    analysisResult: null,
  }),
```

**Step 3: Modify main.tsx — register push event handler**

Replace the entire file with:

```typescript
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { useStore } from './store';
import './globals.css';

declare global {
  interface Window {
    __shieldtier_push?: (event: string, data: unknown) => void;
  }
}

// Native → renderer push event dispatcher.
// Called from C++ via CefExecuteJavaScript.
window.__shieldtier_push = (event: string, data: unknown) => {
  const store = useStore.getState();
  const d = data as Record<string, unknown>;

  switch (event) {
    case 'analysis_complete':
      store.setAnalysis(
        d.sha256 as string,
        d.result as Parameters<typeof store.setAnalysis>[1],
      );
      break;
    case 'download_detected':
      store.setCurrentSha256(d.sha256 as string);
      store.setCurrentDownload({
        sha256: d.sha256 as string,
        filename: d.filename as string,
        size: d.size as number,
      });
      break;
    case 'vm_event':
      store.addVmEvent(d as Parameters<typeof store.addVmEvent>[0]);
      break;
    case 'vm_status':
      store.setVmStatus((d as { status: string }).status as Parameters<typeof store.setVmStatus>[0]);
      break;
    case 'vm_findings':
      store.setVmFindings(d as unknown as Parameters<typeof store.setVmFindings>[0]);
      break;
    case 'vm_process_tree':
      store.setVmProcessTree(d as unknown as Parameters<typeof store.setVmProcessTree>[0]);
      break;
    case 'vm_network_summary':
      store.setVmNetworkSummary(d as Parameters<typeof store.setVmNetworkSummary>[0]);
      break;
    case 'capture_update':
      store.setCaptureData(d as Parameters<typeof store.setCaptureData>[0]);
      break;
    case 'navigation_state':
      store.setNavState(d as Parameters<typeof store.setNavState>[0]);
      break;
  }
};

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

**Step 4: Verify renderer builds**

```bash
cd src/renderer && npx tsc --noEmit && npx vite build
```

**Step 5: Commit**

```bash
git add src/renderer/src/main.tsx src/renderer/src/store/index.ts \
        src/renderer/src/ipc/types.ts
git commit -m "feat(wave4): add renderer push event handler and navigation state to store"
```

---

### Task 5: Response Filter Wiring and Auto-Analysis

Wire `GetResourceResponseFilter()` to detect downloads, capture them in-memory, store in SessionManager, and auto-trigger analysis.

**Files:**
- Modify: `src/native/browser/response_filter.h`
- Modify: `src/native/browser/response_filter.cpp`
- Modify: `src/native/browser/request_handler.h`
- Modify: `src/native/browser/request_handler.cpp`
- Modify: `src/native/browser/session_manager.h`
- Modify: `src/native/browser/session_manager.cpp`

**Step 1: Modify response_filter.h — add completion callback to DownloadCaptureFilter**

Add `#include <functional>` after line 6:

```cpp
#include <functional>
```

Add callback type before the class (after line 14):

```cpp
using FilterCompleteCallback = std::function<void(
    std::string sha256, std::vector<uint8_t> data,
    std::string url, std::string mime_type)>;
```

Change `DownloadCaptureFilter` constructor (line 25) to accept callback:

```cpp
    DownloadCaptureFilter(const std::string& url, const std::string& mime_type,
                          FilterCompleteCallback on_complete = nullptr);
```

Add to private members (after `bool overflow_` on line 45):

```cpp
    FilterCompleteCallback on_complete_;
```

**Step 2: Modify response_filter.cpp — fire callback on filter completion**

Update `DownloadCaptureFilter` constructor to store the callback. Find the constructor implementation and change it to:

```cpp
DownloadCaptureFilter::DownloadCaptureFilter(const std::string& url,
                                              const std::string& mime_type,
                                              FilterCompleteCallback on_complete)
    : url_(url), mime_type_(mime_type), on_complete_(std::move(on_complete)) {}
```

In the `DownloadCaptureFilter::Filter()` method, just before `return RESPONSE_FILTER_DONE;`, add:

```cpp
        if (on_complete_) {
            on_complete_(sha256_hex_, std::move(buffer_), url_, mime_type_);
            on_complete_ = nullptr;
        }
```

**Step 3: Modify session_manager.h — add captured file storage**

Add `#include <mutex>` after line 5:

```cpp
#include <mutex>
```

Add public methods after `get_captured_download` (after line 37):

```cpp
    void store_captured_file(const std::string& sha256,
                             std::vector<uint8_t>&& data,
                             const std::string& filename,
                             const std::string& mime_type);
```

Add private members after `pending_tabs_` (after line 50):

```cpp
    std::unordered_map<std::string, FileBuffer> captured_files_;
    std::mutex captured_mutex_;
```

**Step 4: Modify session_manager.cpp — implement file storage**

Replace the `get_captured_download` stub with:

```cpp
std::optional<FileBuffer> SessionManager::get_captured_download(
        const std::string& sha256) {
    std::lock_guard<std::mutex> lock(captured_mutex_);
    auto it = captured_files_.find(sha256);
    if (it == captured_files_.end()) return std::nullopt;
    return it->second;
}

void SessionManager::store_captured_file(const std::string& sha256,
                                          std::vector<uint8_t>&& data,
                                          const std::string& filename,
                                          const std::string& mime_type) {
    FileBuffer fb;
    fb.data = std::move(data);
    fb.filename = filename;
    fb.mime_type = mime_type;
    fb.sha256 = sha256;

    std::lock_guard<std::mutex> lock(captured_mutex_);
    captured_files_[sha256] = std::move(fb);
}
```

**Step 5: Modify request_handler.h — add download callback and EventBridge setter**

Add includes after line 4:

```cpp
#include <functional>
#include "ipc/event_bridge.h"
```

Add public methods after `set_message_router` (after line 16):

```cpp
    using DownloadCallback = std::function<void(
        const std::string& sha256, const std::string& url,
        const std::string& mime_type)>;

    void set_download_callback(DownloadCallback cb) {
        download_callback_ = std::move(cb);
    }

    void set_event_bridge(EventBridge* bridge) {
        event_bridge_ = bridge;
    }
```

Add private members after `message_router_` (after line 51):

```cpp
    DownloadCallback download_callback_;
    EventBridge* event_bridge_ = nullptr;
```

**Step 6: Modify request_handler.cpp — implement GetResourceResponseFilter**

Add includes at top:

```cpp
#include "browser/response_filter.h"
#include "browser/session_manager.h"
```

Replace the `GetResourceResponseFilter` implementation (currently returns nullptr) with:

```cpp
CefRefPtr<CefResponseFilter> RequestHandler::GetResourceResponseFilter(
    CefRefPtr<CefBrowser> /*browser*/, CefRefPtr<CefFrame> /*frame*/,
    CefRefPtr<CefRequest> request, CefRefPtr<CefResponse> response) {

    if (!is_download_response(request, response)) {
        return nullptr;
    }

    std::string url = request->GetURL().ToString();
    std::string mime = response->GetMimeType().ToString();

    if (should_accumulate(response)) {
        FilterCompleteCallback on_complete = [this](
            std::string sha256, std::vector<uint8_t> data,
            std::string file_url, std::string mime_type) {
            // Extract filename from URL
            auto last_slash = file_url.rfind('/');
            std::string filename = last_slash != std::string::npos
                ? file_url.substr(last_slash + 1) : "download";
            auto query_pos = filename.find('?');
            if (query_pos != std::string::npos) {
                filename = filename.substr(0, query_pos);
            }

            if (download_callback_) {
                download_callback_(sha256, file_url, mime_type);
            }

            if (event_bridge_) {
                event_bridge_->push_download_detected(
                    sha256, filename, data.size());
            }
        };

        return new DownloadCaptureFilter(url, mime, std::move(on_complete));
    }

    return new StreamingHashFilter(url, mime);
}
```

**Step 7: Wire the download callback in shieldtier_client.cpp**

Add to the constructor after `request_handler_->set_event_bridge(event_bridge_.get());`:

```cpp
    auto* sm = session_manager_.get();
    auto* mh = message_handler_.get();
    request_handler_->set_download_callback(
        [sm, mh](const std::string& sha256, const std::string& /*url*/,
                  const std::string& mime_type) {
            // File data already stored in SessionManager by the filter callback.
            // Trigger auto-analysis.
            mh->auto_analyze(sha256);
        });
```

Wait — the download callback in RequestHandler fires AFTER the filter completes but the file data is passed to the filter's on_complete, not stored yet. We need the filter's on_complete to ALSO store the data. Let me fix the design:

The filter's on_complete callback should:
1. Store the captured data in SessionManager
2. Then trigger analysis

So in the RequestHandler's GetResourceResponseFilter, the on_complete should also do the storage. But RequestHandler doesn't have a pointer to SessionManager. We need to pass it through.

**Revised Step 6: Modify request_handler.h — add SessionManager and MessageHandler pointers**

Replace the callback approach with direct pointers. Change `set_download_callback` and private members to:

```cpp
    void set_session_manager(SessionManager* sm) { session_manager_ = sm; }
    void set_message_handler(MessageHandler* mh) { message_handler_ = mh; }
    void set_event_bridge(EventBridge* bridge) { event_bridge_ = bridge; }
```

Private members:

```cpp
    SessionManager* session_manager_ = nullptr;
    MessageHandler* message_handler_ = nullptr;
    EventBridge* event_bridge_ = nullptr;
```

**Revised Step 6 continued: request_handler.cpp GetResourceResponseFilter**

Add forward declaration include:

```cpp
#include "ipc/message_handler.h"
```

Replace implementation:

```cpp
CefRefPtr<CefResponseFilter> RequestHandler::GetResourceResponseFilter(
    CefRefPtr<CefBrowser> /*browser*/, CefRefPtr<CefFrame> /*frame*/,
    CefRefPtr<CefRequest> request, CefRefPtr<CefResponse> response) {

    if (!is_download_response(request, response)) {
        return nullptr;
    }

    std::string url = request->GetURL().ToString();
    std::string mime = response->GetMimeType().ToString();

    if (!should_accumulate(response)) {
        return new StreamingHashFilter(url, mime);
    }

    auto* sm = session_manager_;
    auto* mh = message_handler_;
    auto* bridge = event_bridge_;

    FilterCompleteCallback on_complete = [sm, mh, bridge](
        std::string sha256, std::vector<uint8_t> data,
        std::string file_url, std::string mime_type) {
        // Extract filename from URL
        auto last_slash = file_url.rfind('/');
        std::string filename = last_slash != std::string::npos
            ? file_url.substr(last_slash + 1) : "download";
        auto qpos = filename.find('?');
        if (qpos != std::string::npos) filename = filename.substr(0, qpos);

        size_t file_size = data.size();

        // Store captured file in session manager
        if (sm) {
            sm->store_captured_file(sha256, std::move(data), filename, mime_type);
        }

        // Notify renderer
        if (bridge) {
            bridge->push_download_detected(sha256, filename, file_size);
        }

        // Auto-trigger analysis
        if (mh) {
            mh->auto_analyze(sha256);
        }
    };

    return new DownloadCaptureFilter(url, mime, std::move(on_complete));
}
```

**Revised Step 7: Wire in shieldtier_client.cpp**

Replace the download_callback wiring. In the constructor, after creating event_bridge, add:

```cpp
    request_handler_->set_session_manager(session_manager_.get());
    request_handler_->set_message_handler(message_handler_.get());
    request_handler_->set_event_bridge(event_bridge_.get());
```

Remove the old `download_callback_` related code (it's replaced by direct pointers).

**Step 8: Commit**

```bash
git add src/native/browser/response_filter.h src/native/browser/response_filter.cpp \
        src/native/browser/request_handler.h src/native/browser/request_handler.cpp \
        src/native/browser/session_manager.h src/native/browser/session_manager.cpp \
        src/native/app/shieldtier_client.cpp
git commit -m "feat(wave4): wire response filter → auto-analysis pipeline with EventBridge push"
```

---

### Task 6: Navigation IPC Actions

Add IPC actions for browser navigation control: back, forward, reload, stop.

**Files:**
- Modify: `src/native/ipc/ipc_protocol.h`
- Modify: `src/native/ipc/message_handler.h`
- Modify: `src/native/ipc/message_handler.cpp`

**Step 1: Add navigation action constants to ipc_protocol.h**

Add after `kActionGetCapture` (line 20):

```cpp
inline constexpr const char* kActionNavBack = "nav_back";
inline constexpr const char* kActionNavForward = "nav_forward";
inline constexpr const char* kActionNavReload = "nav_reload";
inline constexpr const char* kActionNavStop = "nav_stop";
```

**Step 2: Add handler declarations to message_handler.h**

Add after `handle_get_capture` (line 57):

```cpp
    json handle_nav_back(CefRefPtr<CefBrowser> browser, const json& payload);
    json handle_nav_forward(CefRefPtr<CefBrowser> browser, const json& payload);
    json handle_nav_reload(CefRefPtr<CefBrowser> browser, const json& payload);
    json handle_nav_stop(CefRefPtr<CefBrowser> browser, const json& payload);
```

**Step 3: Add dispatch cases and handler implementations to message_handler.cpp**

Add dispatch cases in `OnQuery` after the `kActionGetCapture` case (after line 69):

```cpp
        } else if (req.action == ipc::kActionNavBack) {
            result = handle_nav_back(browser, req.payload);
        } else if (req.action == ipc::kActionNavForward) {
            result = handle_nav_forward(browser, req.payload);
        } else if (req.action == ipc::kActionNavReload) {
            result = handle_nav_reload(browser, req.payload);
        } else if (req.action == ipc::kActionNavStop) {
            result = handle_nav_stop(browser, req.payload);
```

Add handler implementations before the closing `}  // namespace`:

```cpp
json MessageHandler::handle_nav_back(CefRefPtr<CefBrowser> browser,
                                      const json& /*payload*/) {
    Navigation::go_back(browser);
    return ipc::make_success();
}

json MessageHandler::handle_nav_forward(CefRefPtr<CefBrowser> browser,
                                         const json& /*payload*/) {
    Navigation::go_forward(browser);
    return ipc::make_success();
}

json MessageHandler::handle_nav_reload(CefRefPtr<CefBrowser> browser,
                                        const json& /*payload*/) {
    Navigation::reload(browser);
    return ipc::make_success();
}

json MessageHandler::handle_nav_stop(CefRefPtr<CefBrowser> browser,
                                      const json& /*payload*/) {
    Navigation::stop(browser);
    return ipc::make_success();
}
```

**Step 4: Commit**

```bash
git add src/native/ipc/ipc_protocol.h src/native/ipc/message_handler.h \
        src/native/ipc/message_handler.cpp
git commit -m "feat(wave4): add navigation IPC actions — back, forward, reload, stop"
```

---

### Task 7: BrowserZone Navigation Wiring

Wire the BrowserZone component to use navigation IPC actions and read navigation state from the store.

**Files:**
- Modify: `src/renderer/src/components/workspace/BrowserZone.tsx`

**Step 1: Replace BrowserZone.tsx with fully wired version**

```tsx
import { useState, useCallback } from 'react';
import { Badge } from '../common/Badge';
import { ipcCall } from '../../ipc/bridge';
import { useStore } from '../../store';

export function BrowserZone() {
  const { navCanGoBack, navCanGoForward, navIsLoading, navCurrentUrl } = useStore();
  const [urlInput, setUrlInput] = useState('');

  const navigate = useCallback(async () => {
    const trimmed = urlInput.trim();
    if (!trimmed) return;

    let target = trimmed;
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = 'https://' + target;
    }

    try {
      await ipcCall('navigate', { url: target });
    } catch (e) {
      console.error('Navigation failed:', e);
    }
  }, [urlInput]);

  const onKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') navigate();
  }, [navigate]);

  const goBack = useCallback(() => { ipcCall('nav_back'); }, []);
  const goForward = useCallback(() => { ipcCall('nav_forward'); }, []);
  const reload = useCallback(() => {
    if (navIsLoading) {
      ipcCall('nav_stop');
    } else {
      ipcCall('nav_reload');
    }
  }, [navIsLoading]);

  const displayUrl = urlInput || navCurrentUrl;

  return (
    <div className="flex flex-col h-full bg-[var(--st-bg-primary)]">
      <div className="flex items-center h-10 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0 bg-[var(--st-bg-panel)]">
        <div className="flex items-center gap-1 flex-shrink-0">
          <NavButton label="Back" onClick={goBack} disabled={!navCanGoBack}>
            <path d="M19 12H5M12 19l-7-7 7-7" />
          </NavButton>
          <NavButton label="Forward" onClick={goForward} disabled={!navCanGoForward}>
            <path d="M5 12h14M12 5l7 7-7 7" />
          </NavButton>
          <NavButton label={navIsLoading ? 'Stop' : 'Refresh'} onClick={reload}>
            {navIsLoading ? (
              <path d="M18 6L6 18M6 6l12 12" />
            ) : (
              <>
                <path d="M23 4v6h-6M1 20v-6h6" />
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
              </>
            )}
          </NavButton>
        </div>

        <Badge severity="info" className="flex-shrink-0">SANDBOXED</Badge>

        <div className="flex-1 flex items-center bg-[var(--st-bg-primary)] rounded border border-[var(--st-border)] px-2 h-7">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--st-text-muted)" strokeWidth="2" className="flex-shrink-0 mr-1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <input
            type="text"
            value={displayUrl}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={onKeyDown}
            onFocus={() => { if (!urlInput && navCurrentUrl) setUrlInput(navCurrentUrl); }}
            placeholder="Enter URL to investigate..."
            className="flex-1 bg-transparent border-none outline-none text-[var(--st-text-primary)] font-mono text-[11px] placeholder:text-[var(--st-text-muted)]"
          />
          {navIsLoading && (
            <div className="w-3 h-3 border-2 border-[var(--st-accent)] border-t-transparent rounded-full animate-spin flex-shrink-0" />
          )}
        </div>
      </div>

      {!navCurrentUrl || navCurrentUrl === 'about:blank' || navCurrentUrl.startsWith('shieldtier://') ? (
        <div className="flex-1 flex items-center justify-center bg-[var(--st-bg-primary)]">
          <div className="flex flex-col items-center gap-3 text-[var(--st-text-muted)]">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" opacity="0.3">
              <circle cx="12" cy="12" r="10" />
              <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
            </svg>
            <span className="text-[11px]">Navigate to a URL to begin analysis</span>
          </div>
        </div>
      ) : (
        <div className="flex-1 bg-[var(--st-bg-primary)]" />
      )}
    </div>
  );
}

function NavButton({ label, children, onClick, disabled }: {
  label: string;
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      title={label}
      onClick={onClick}
      disabled={disabled}
      className="w-7 h-7 rounded border-none bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)] cursor-pointer transition-colors flex items-center justify-center disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:bg-transparent"
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        {children}
      </svg>
    </button>
  );
}
```

**Step 2: Verify renderer builds**

```bash
cd src/renderer && npx tsc --noEmit && npx vite build
```

**Step 3: Commit**

```bash
git add src/renderer/src/components/workspace/BrowserZone.tsx
git commit -m "feat(wave4): wire BrowserZone nav buttons to IPC with live state from store"
```

---

### Task 8: VM Control IPC and VMControls Wiring

Add IPC actions to start/stop VMs and submit samples. Wire VMControls buttons to call them.

**Files:**
- Modify: `src/native/ipc/ipc_protocol.h`
- Modify: `src/native/ipc/message_handler.h`
- Modify: `src/native/ipc/message_handler.cpp`
- Modify: `src/renderer/src/components/vm/VMControls.tsx`

**Step 1: Add VM action constants to ipc_protocol.h**

Add after the nav action constants:

```cpp
inline constexpr const char* kActionStartVm = "start_vm";
inline constexpr const char* kActionStopVm = "stop_vm";
inline constexpr const char* kActionSubmitSampleToVm = "submit_sample_to_vm";
```

**Step 2: Add VM handler declarations to message_handler.h**

Add include after existing includes:

```cpp
#include "vm/vm_manager.h"
```

Add handler declarations after the nav handlers:

```cpp
    json handle_start_vm(const json& payload);
    json handle_stop_vm(const json& payload);
    json handle_submit_sample_to_vm(const json& payload);
```

Add VmManager member after `export_manager_` (in the private section):

```cpp
    std::unique_ptr<VmManager> vm_manager_;
```

**Step 3: Add dispatch and implementations to message_handler.cpp**

Add `#include "vm/vm_scoring.h"` to the includes.

Add `vm_manager_(std::make_unique<VmManager>()),` to the constructor initializer list (after `export_manager_`).

Add dispatch cases in `OnQuery` after the nav cases:

```cpp
        } else if (req.action == ipc::kActionStartVm) {
            result = handle_start_vm(req.payload);
        } else if (req.action == ipc::kActionStopVm) {
            result = handle_stop_vm(req.payload);
        } else if (req.action == ipc::kActionSubmitSampleToVm) {
            result = handle_submit_sample_to_vm(req.payload);
```

Add handler implementations:

```cpp
json MessageHandler::handle_start_vm(const json& payload) {
    std::string os = payload.value("os", "alpine");

    VmConfig config;
    if (os.find("windows") != std::string::npos || os.find("Windows") != std::string::npos) {
        config.platform = VmPlatform::Windows;
    } else {
        config.platform = VmPlatform::Linux;
    }

    auto result = vm_manager_->create_vm(config);
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }

    std::string vm_id = result.value();

    auto start_result = vm_manager_->start_vm(vm_id);
    if (!start_result.ok()) {
        return ipc::make_error(start_result.error().message);
    }

    if (event_bridge_) {
        event_bridge_->push_vm_status("booting");
    }

    // Monitor VM in background thread
    auto* vm_mgr = vm_manager_.get();
    auto* bridge = event_bridge_;

    std::jthread monitor([vm_id, vm_mgr, bridge](std::stop_token stop) {
        // Wait for VM to become ready
        while (!stop.stop_requested()) {
            auto state = vm_mgr->get_state(vm_id);
            if (!state.ok()) break;

            if (state.value() == VmState::kReady || state.value() == VmState::kRunning) {
                if (bridge) bridge->push_vm_status("running");
                break;
            }
            if (state.value() == VmState::kError) {
                if (bridge) bridge->push_vm_status("error");
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        analysis_threads_.push_back(std::move(monitor));
    }

    return ipc::make_success({{"vm_id", vm_id}});
}

json MessageHandler::handle_stop_vm(const json& payload) {
    std::string vm_id = payload.value("vm_id", "");

    // If no vm_id, stop all VMs
    auto vms = vm_manager_->list_vms();
    if (vm_id.empty() && !vms.empty()) {
        vm_id = vms.front().id;
    }

    if (vm_id.empty()) {
        return ipc::make_error("no_active_vm");
    }

    auto result = vm_manager_->stop_vm(vm_id);
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }

    if (event_bridge_) {
        event_bridge_->push_vm_status("idle");
    }

    return ipc::make_success();
}

json MessageHandler::handle_submit_sample_to_vm(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) {
        return ipc::make_error("sha256_required");
    }

    auto file_opt = session_manager_->get_captured_download(sha256);
    if (!file_opt.has_value()) {
        return ipc::make_error("download_not_found");
    }

    auto vms = vm_manager_->list_vms();
    if (vms.empty()) {
        return ipc::make_error("no_active_vm");
    }

    std::string vm_id = vms.front().id;
    auto result = vm_manager_->submit_sample(vm_id, file_opt.value());
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }

    if (event_bridge_) {
        event_bridge_->push_vm_status("running");
    }

    return ipc::make_success({{"vm_id", vm_id}});
}
```

**Step 4: Wire VMControls.tsx buttons to IPC**

Replace the entire file with:

```tsx
import { useState, useCallback } from 'react';
import { cn } from '../../lib/utils';
import { Badge } from '../common/Badge';
import { StatusDot } from '../common/StatusDot';
import { useStore } from '../../store';
import { ipcCall } from '../../ipc/bridge';

const OS_OPTIONS = ['Alpine 3.19', 'ReactOS 0.4', 'Windows 10 x64'];

export function VMControls() {
  const { vmStatus } = useStore();
  const [selectedOs, setSelectedOs] = useState(OS_OPTIONS[0]);

  const statusLabel = vmStatus === 'running' ? 'RUNNING' : vmStatus === 'booting' ? 'BOOTING' : vmStatus === 'complete' ? 'COMPLETE' : 'IDLE';
  const statusSeverity = vmStatus === 'running' ? 'clean' : vmStatus === 'booting' ? 'medium' : vmStatus === 'complete' ? 'info' : 'low';
  const dotStatus = vmStatus === 'running' ? 'active' as const : vmStatus === 'error' ? 'error' as const : 'idle' as const;

  const startVm = useCallback(async () => {
    if (vmStatus !== 'idle' && vmStatus !== 'complete') return;
    try {
      await ipcCall('start_vm', { os: selectedOs });
    } catch (e) {
      console.error('Failed to start VM:', e);
    }
  }, [vmStatus, selectedOs]);

  const stopVm = useCallback(async () => {
    if (vmStatus !== 'running' && vmStatus !== 'booting') return;
    try {
      await ipcCall('stop_vm', {});
    } catch (e) {
      console.error('Failed to stop VM:', e);
    }
  }, [vmStatus]);

  return (
    <div className="flex items-center h-8 px-2 gap-2 border-b border-[var(--st-border)] bg-[var(--st-bg-panel)] flex-shrink-0">
      <select
        value={selectedOs}
        onChange={(e) => setSelectedOs(e.target.value)}
        disabled={vmStatus === 'running' || vmStatus === 'booting'}
        className="bg-[var(--st-bg-primary)] border border-[var(--st-border)] rounded text-[var(--st-text-label)] text-[10px] font-mono px-1.5 py-0.5 outline-none cursor-pointer disabled:opacity-50"
      >
        {OS_OPTIONS.map((os) => (
          <option key={os} value={os}>{os}</option>
        ))}
      </select>

      <div className="flex items-center gap-1.5">
        <StatusDot status={dotStatus} />
        <Badge severity={statusSeverity}>{statusLabel}</Badge>
      </div>

      <div className="flex items-center gap-1">
        <button
          onClick={startVm}
          disabled={vmStatus !== 'idle' && vmStatus !== 'complete'}
          className={cn(
            'px-2 py-0.5 rounded text-[10px] font-bold border-none cursor-pointer transition-colors',
            (vmStatus === 'idle' || vmStatus === 'complete')
              ? 'bg-[var(--st-severity-clean)]/15 text-[var(--st-severity-clean)] hover:bg-[var(--st-severity-clean)]/25'
              : 'bg-[var(--st-bg-hover)] text-[var(--st-text-muted)] cursor-not-allowed',
          )}
        >
          START
        </button>
        <button
          onClick={stopVm}
          disabled={vmStatus !== 'running' && vmStatus !== 'booting'}
          className={cn(
            'px-2 py-0.5 rounded text-[10px] font-bold border-none cursor-pointer transition-colors',
            (vmStatus === 'running' || vmStatus === 'booting')
              ? 'bg-[var(--st-severity-critical)]/15 text-[var(--st-severity-critical)] hover:bg-[var(--st-severity-critical)]/25'
              : 'bg-[var(--st-bg-hover)] text-[var(--st-text-muted)] cursor-not-allowed',
          )}
        >
          STOP
        </button>
      </div>

      <div className="flex-1" />

      {(vmStatus === 'running' || vmStatus === 'booting') && (
        <Badge severity="critical" className="animate-pulse">
          {vmStatus === 'booting' ? 'BOOTING...' : 'LIVE - ANALYZING'}
        </Badge>
      )}
    </div>
  );
}
```

**Step 5: Verify renderer builds**

```bash
cd src/renderer && npx tsc --noEmit && npx vite build
```

**Step 6: Commit**

```bash
git add src/native/ipc/ipc_protocol.h src/native/ipc/message_handler.h \
        src/native/ipc/message_handler.cpp \
        src/renderer/src/components/vm/VMControls.tsx
git commit -m "feat(wave4): add VM control IPC — start/stop VM, wire VMControls buttons"
```

---

### Task 9: Build Verification and Final Cleanup

Verify both the native CMakeLists and the renderer build with all changes in place.

**Files:**
- Modify: `src/native/CMakeLists.txt` (verify all new sources are listed)
- No new files

**Step 1: Verify CMakeLists.txt has all new sources**

The source list should include (after all previous tasks):
```
    browser/scheme_handler.cpp
    ipc/event_bridge.cpp
```

These were added in Tasks 1 and 2. Verify with:

```bash
grep -n "scheme_handler\|event_bridge" src/native/CMakeLists.txt
```

**Step 2: Verify renderer TypeScript compilation**

```bash
cd src/renderer && npx tsc --noEmit
```

Expected: No errors.

**Step 3: Verify renderer production build**

```bash
cd src/renderer && npx vite build
```

Expected: Build succeeds with JS + CSS output.

**Step 4: Verify no regressions — check all modified files compile**

For the native side, if you have CMake configured:

```bash
cd build && cmake --build . 2>&1 | tail -20
```

If CMake is not configured (typical for dev without CEF SDK), the TypeScript/renderer verification is sufficient.

**Step 5: Commit if any cleanup was needed**

```bash
git add -A
git commit -m "chore(wave4): final build verification and cleanup"
```

---

## Summary

| Task | What | New Files | Modified Files |
|------|------|-----------|---------------|
| 1 | Custom scheme handler | `scheme_handler.h/.cpp` | `shieldtier_app.h/.cpp`, `CMakeLists.txt` |
| 2 | EventBridge native | `event_bridge.h/.cpp` | `CMakeLists.txt` |
| 3 | Wire EventBridge | — | `shieldtier_client.h/.cpp`, `message_handler.h/.cpp` |
| 4 | Renderer push handler | — | `main.tsx`, `store/index.ts`, `types.ts` |
| 5 | Response filter + auto-analyze | — | `response_filter.h/.cpp`, `request_handler.h/.cpp`, `session_manager.h/.cpp`, `shieldtier_client.cpp` |
| 6 | Navigation IPC | — | `ipc_protocol.h`, `message_handler.h/.cpp` |
| 7 | BrowserZone wiring | — | `BrowserZone.tsx` |
| 8 | VM control IPC + VMControls | — | `ipc_protocol.h`, `message_handler.h/.cpp`, `VMControls.tsx` |
| 9 | Build verification | — | `CMakeLists.txt` (verify) |

**New files:** 4 (`scheme_handler.h/.cpp`, `event_bridge.h/.cpp`)
**Modified files:** ~18 across native + renderer
**Estimated commits:** 9
