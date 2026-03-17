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

    std::string payload = data.dump(-1, ' ', false, json::error_handler_t::replace);
    // Escape U+2028/U+2029 — valid in JSON but line terminators in JavaScript
    for (size_t pos = 0; pos < payload.size(); ++pos) {
        if (payload[pos] == '\xe2' && pos + 2 < payload.size() &&
            payload[pos + 1] == '\x80' &&
            (payload[pos + 2] == '\xa8' || payload[pos + 2] == '\xa9')) {
            std::string esc = payload[pos + 2] == '\xa8' ? "\\u2028" : "\\u2029";
            payload.replace(pos, 3, esc);
            pos += 5;
        }
    }
    std::string js = "window.__shieldtier_push&&window.__shieldtier_push('"
        + event + "'," + payload + ")";

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

void EventBridge::push_load_error(int code, const std::string& text,
                                   const std::string& url) {
    push("load_error", {{"code", code}, {"text", text}, {"url", url}});
}

void EventBridge::push_screenshot(const std::string& url) {
    push("screenshot", {{"url", url}});
}

void EventBridge::push_dom_snapshot(const json& snapshot) {
    push("dom_snapshot", snapshot);
}

void EventBridge::push_email_parsed(const json& email) {
    push("email_parsed", email);
}

void EventBridge::push_log_progress(const std::string& id,
                                     const std::string& file_name,
                                     const std::string& status) {
    push("log_progress", {{"id", id}, {"fileName", file_name}, {"status", status}});
}

void EventBridge::push_log_complete(const std::string& id,
                                     const json& result) {
    push("log_complete", {{"id", id}, {"result", result}});
}

}  // namespace shieldtier
