#pragma once

#include "include/cef_request_handler.h"
#include "include/cef_resource_request_handler.h"
#include "include/wrapper/cef_message_router.h"

#include <functional>
#include <unordered_map>
#include <chrono>
#include <mutex>

#include "ipc/event_bridge.h"
#include "capture/capture_manager.h"

namespace shieldtier {

class SessionManager;
class MessageHandler;

class RequestHandler : public CefRequestHandler,
                       public CefResourceRequestHandler {
public:
    RequestHandler() = default;

    void set_message_router(CefRefPtr<CefMessageRouterBrowserSide> router) {
        message_router_ = router;
    }

    void set_event_bridge(shieldtier::EventBridge* bridge) {
        event_bridge_ = bridge;
    }

    void set_session_manager(SessionManager* sm) { session_manager_ = sm; }
    void set_message_handler(MessageHandler* mh) { message_handler_ = mh; }
    void set_capture_manager(CaptureManager* cm) { capture_manager_ = cm; }
    void set_ui_browser_id(int id) { ui_browser_id_ = id; }

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

    void OnRenderProcessTerminated(CefRefPtr<CefBrowser> browser,
                                    TerminationStatus status,
                                    int error_code,
                                    const CefString& error_string) override;

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

    void OnResourceLoadComplete(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefRefPtr<CefRequest> request,
        CefRefPtr<CefResponse> response,
        URLRequestStatus status,
        int64_t received_content_length) override;

private:
    CefRefPtr<CefMessageRouterBrowserSide> message_router_;
    shieldtier::EventBridge* event_bridge_ = nullptr;
    SessionManager* session_manager_ = nullptr;
    MessageHandler* message_handler_ = nullptr;
    CaptureManager* capture_manager_ = nullptr;
    int ui_browser_id_ = -1;

    // Track request start times for timing calculation
    std::mutex timing_mutex_;
    std::unordered_map<std::string, int64_t> request_start_times_;

    IMPLEMENT_REFCOUNTING(RequestHandler);
    DISALLOW_COPY_AND_ASSIGN(RequestHandler);
};

}  // namespace shieldtier
