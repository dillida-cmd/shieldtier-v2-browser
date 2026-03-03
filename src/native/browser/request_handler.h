#pragma once

#include "include/cef_request_handler.h"
#include "include/cef_resource_request_handler.h"
#include "include/wrapper/cef_message_router.h"

#include <functional>

#include "ipc/event_bridge.h"

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
                                    TerminationStatus status) override;

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
    CefRefPtr<CefMessageRouterBrowserSide> message_router_;
    shieldtier::EventBridge* event_bridge_ = nullptr;
    SessionManager* session_manager_ = nullptr;
    MessageHandler* message_handler_ = nullptr;

    IMPLEMENT_REFCOUNTING(RequestHandler);
    DISALLOW_COPY_AND_ASSIGN(RequestHandler);
};

}  // namespace shieldtier
