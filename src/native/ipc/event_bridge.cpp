#include "ipc/event_bridge.h"

namespace shieldtier {

namespace {

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
