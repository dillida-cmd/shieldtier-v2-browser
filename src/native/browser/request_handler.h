#pragma once

#include "include/cef_request_handler.h"
#include "include/cef_resource_request_handler.h"

namespace shieldtier {

class RequestHandler : public CefRequestHandler,
                       public CefResourceRequestHandler {
public:
    RequestHandler() = default;

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
    static bool is_unsafe_scheme(const std::string& url);
    static bool is_private_ip(const std::string& host);

    IMPLEMENT_REFCOUNTING(RequestHandler);
    DISALLOW_COPY_AND_ASSIGN(RequestHandler);
};

}  // namespace shieldtier
