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

#include "browser/response_filter.h"
#include "browser/session_manager.h"
#include "ipc/message_handler.h"

namespace shieldtier {

namespace {

struct Ipv4Range {
    uint32_t network;
    uint32_t mask;
};

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

bool is_unsafe_scheme(const std::string& url) {
    auto starts_with = [&](const char* prefix) {
        return url.compare(0, strlen(prefix), prefix) == 0;
    };
    return starts_with("javascript:") ||
           starts_with("vbscript:") ||
           starts_with("data:text/html") ||
           starts_with("data:text/xhtml") ||
           starts_with("data:image/svg+xml");
}

bool is_private_ipv4(const std::string& host) {
    struct in_addr addr {};
    if (inet_pton(AF_INET, host.c_str(), &addr) != 1) {
        return false;
    }

#ifndef NDEBUG
    struct in_addr localhost_addr {};
    inet_pton(AF_INET, "127.0.0.1", &localhost_addr);
    if (addr.s_addr == localhost_addr.s_addr) {
        return false;
    }
#endif

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

bool is_private_ipv6(const std::string& host) {
    struct in6_addr addr {};
    if (inet_pton(AF_INET6, host.c_str(), &addr) != 1) {
        return false;
    }

    uint8_t* b = addr.s6_addr;

    // ::1 (loopback)
#ifndef NDEBUG
    // Allow ::1 in debug builds
#else
    {
        struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
        if (memcmp(&addr, &loopback, sizeof(addr)) == 0) {
            return true;
        }
    }
#endif

    // fc00::/7 (unique local address)
    if ((b[0] & 0xFE) == 0xFC) {
        return true;
    }

    // fe80::/10 (link-local)
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) {
        return true;
    }

    // ::ffff:0:0/96 (IPv4-mapped) — check the mapped IPv4 address
    bool is_v4_mapped = (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
                         b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
                         b[8] == 0 && b[9] == 0 && b[10] == 0xFF && b[11] == 0xFF);
    if (is_v4_mapped) {
        char v4_str[INET_ADDRSTRLEN];
        struct in_addr v4_addr {};
        memcpy(&v4_addr, &b[12], 4);
        inet_ntop(AF_INET, &v4_addr, v4_str, sizeof(v4_str));
        return is_private_ipv4(v4_str);
    }

    return false;
}

bool is_private_ip(const std::string& host) {
    return is_private_ipv4(host) || is_private_ipv6(host);
}

std::string extract_host(const std::string& url) {
    auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        return {};
    }
    auto host_start = scheme_end + 3;
    auto host_end = url.find_first_of(":/?#", host_start);
    size_t host_len = (host_end == std::string::npos) ? std::string::npos
                                                      : host_end - host_start;
    return url.substr(host_start, host_len);
}

}  // namespace

bool RequestHandler::OnBeforeBrowse(CefRefPtr<CefBrowser> browser,
                                    CefRefPtr<CefFrame> frame,
                                    CefRefPtr<CefRequest> request,
                                    bool /*user_gesture*/,
                                    bool /*is_redirect*/) {
    std::string url = request->GetURL().ToString();

    if (is_unsafe_scheme(url)) {
        LOG(WARNING) << "[ShieldTier] Blocked unsafe scheme: " << url;
        return true;
    }

    std::string host = extract_host(url);
    if (!host.empty() && is_private_ip(host)) {
        LOG(WARNING) << "[ShieldTier] Blocked navigation to private IP: " << host;
        return true;
    }

    if (message_router_) {
        message_router_->OnBeforeBrowse(browser, frame);
    }
    return false;
}

bool RequestHandler::OnCertificateError(CefRefPtr<CefBrowser> /*browser*/,
                                        cef_errorcode_t cert_error,
                                        const CefString& request_url,
                                        CefRefPtr<CefSSLInfo> /*ssl_info*/,
                                        CefRefPtr<CefCallback> callback) {
    LOG(WARNING) << "[ShieldTier] Allowing cert error " << cert_error
                 << " for: " << request_url.ToString();
    callback->Continue();
    return true;
}

void RequestHandler::OnRenderProcessTerminated(
        CefRefPtr<CefBrowser> browser,
        TerminationStatus /*status*/) {
    if (message_router_) {
        message_router_->OnRenderProcessTerminated(browser);
    }
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
    CefRefPtr<CefRequest> request,
    CefRefPtr<CefResponse> response) {

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
        auto last_slash = file_url.rfind('/');
        std::string filename = last_slash != std::string::npos
            ? file_url.substr(last_slash + 1) : "download";
        auto qpos = filename.find('?');
        if (qpos != std::string::npos) filename = filename.substr(0, qpos);

        size_t file_size = data.size();

        if (sm) {
            sm->store_captured_file(sha256, std::move(data), filename, mime_type);
        }

        if (bridge) {
            bridge->push_download_detected(sha256, filename, file_size);
        }

        if (mh) {
            mh->auto_analyze(sha256);
        }
    };

    return new DownloadCaptureFilter(url, mime, std::move(on_complete));
}

}  // namespace shieldtier
