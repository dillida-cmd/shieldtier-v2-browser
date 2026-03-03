#include "browser/request_handler.h"

#include <cstring>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "include/base/cef_logging.h"

namespace shieldtier {

namespace {

struct Ipv4Range {
    uint32_t network;
    uint32_t mask;
};

// Returns true if the parsed IPv4 address falls within the given CIDR range.
bool ipv4_in_range(uint32_t addr, const Ipv4Range& range) {
    return (addr & range.mask) == range.network;
}

uint32_t cidr_mask(int prefix_len) {
    return prefix_len == 0 ? 0 : htonl(~((1u << (32 - prefix_len)) - 1));
}

Ipv4Range make_range(const char* base, int prefix_len) {
    struct in_addr addr {};
    inet_pton(AF_INET, base, &addr);
    uint32_t mask = cidr_mask(prefix_len);
    return {addr.s_addr & mask, mask};
}

}  // namespace

bool RequestHandler::is_unsafe_scheme(const std::string& url) {
    auto starts_with = [&](const char* prefix) {
        return url.compare(0, strlen(prefix), prefix) == 0;
    };
    return starts_with("javascript:") ||
           starts_with("vbscript:") ||
           starts_with("data:text/html");
}

bool RequestHandler::is_private_ip(const std::string& host) {
    struct in_addr addr {};
    if (inet_pton(AF_INET, host.c_str(), &addr) != 1) {
        return false;
    }

    // Allow localhost (127.0.0.1) for dev
    struct in_addr localhost_addr {};
    inet_pton(AF_INET, "127.0.0.1", &localhost_addr);
    if (addr.s_addr == localhost_addr.s_addr) {
        return false;
    }

    static const Ipv4Range kPrivateRanges[] = {
        make_range("10.0.0.0", 8),
        make_range("172.16.0.0", 12),
        make_range("192.168.0.0", 16),
        make_range("127.0.0.0", 8),
        make_range("169.254.0.0", 16),
    };

    for (const auto& range : kPrivateRanges) {
        if (ipv4_in_range(addr.s_addr, range)) {
            return true;
        }
    }
    return false;
}

bool RequestHandler::OnBeforeBrowse(CefRefPtr<CefBrowser> /*browser*/,
                                    CefRefPtr<CefFrame> /*frame*/,
                                    CefRefPtr<CefRequest> request,
                                    bool /*user_gesture*/,
                                    bool /*is_redirect*/) {
    std::string url = request->GetURL().ToString();

    if (is_unsafe_scheme(url)) {
        LOG(WARNING) << "[ShieldTier] Blocked unsafe scheme: " << url;
        return true;
    }

    // Extract host from URL for private IP check.
    // CefURICreate/parse isn't exposed simply, so we parse manually.
    // Expects scheme://host[:port]/... format.
    std::string host;
    auto scheme_end = url.find("://");
    if (scheme_end != std::string::npos) {
        auto host_start = scheme_end + 3;
        auto host_end = url.find_first_of(":/?#", host_start);
        host = url.substr(host_start, host_end - host_start);
    }

    if (!host.empty() && is_private_ip(host)) {
        LOG(WARNING) << "[ShieldTier] Blocked navigation to private IP: " << host;
        return true;
    }

    return false;
}

bool RequestHandler::OnCertificateError(CefRefPtr<CefBrowser> /*browser*/,
                                        cef_errorcode_t cert_error,
                                        const CefString& request_url,
                                        CefRefPtr<CefSSLInfo> /*ssl_info*/,
                                        CefRefPtr<CefCallback> callback) {
    // SOC malware analysis browser must access sites with bad certs
    LOG(WARNING) << "[ShieldTier] Allowing cert error " << cert_error
                 << " for: " << request_url.ToString();
    callback->Continue();
    return true;
}

CefRefPtr<CefResourceRequestHandler> RequestHandler::GetResourceRequestHandler(
    CefRefPtr<CefBrowser> /*browser*/,
    CefRefPtr<CefFrame> /*frame*/,
    CefRefPtr<CefRequest> /*request*/,
    bool /*is_navigation*/,
    bool /*is_download*/,
    const CefString& /*request_initiator*/,
    bool& /*disable_default_handling*/) {
    return this;
}

CefRefPtr<CefResponseFilter> RequestHandler::GetResourceResponseFilter(
    CefRefPtr<CefBrowser> /*browser*/,
    CefRefPtr<CefFrame> /*frame*/,
    CefRefPtr<CefRequest> /*request*/,
    CefRefPtr<CefResponse> /*response*/) {
    // Task 2 builds response filters, Task 6 wires them here
    return nullptr;
}

}  // namespace shieldtier
