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
    void push_load_error(int code, const std::string& text,
                         const std::string& url);

    void push_screenshot(const std::string& url);
    void push_dom_snapshot(const json& snapshot);
    void push_email_parsed(const json& email);
    void push_log_progress(const std::string& id,
                           const std::string& file_name,
                           const std::string& status);
    void push_log_complete(const std::string& id, const json& result);

    void push(const std::string& event, const json& data);

private:

    CefRefPtr<CefBrowser> browser_;
    std::mutex mutex_;
};

}  // namespace shieldtier
