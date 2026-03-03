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

    bool OnQuery(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                 int64_t query_id, const CefString& request, bool persistent,
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
    std::unordered_map<std::string, json> analysis_results_;
};

}  // namespace shieldtier
