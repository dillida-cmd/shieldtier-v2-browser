#include "browser/request_handler.h"

#include <chrono>
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
#include "network/network_policy.h"

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
    fprintf(stderr, "[ShieldTier] OnBeforeBrowse: %s\n", url.c_str());

    if (is_unsafe_scheme(url)) {
        fprintf(stderr, "[ShieldTier] BLOCKED unsafe scheme: %s\n", url.c_str());
        return true;
    }

    std::string host = extract_host(url);
    if (!host.empty() && is_private_ip(host)) {
        fprintf(stderr, "[ShieldTier] BLOCKED private IP: %s\n", host.c_str());
        return true;
    }

    // Block STUN/TURN schemes (WebRTC leak prevention)
    if (NetworkPolicy::is_stun_turn_scheme(url)) {
        fprintf(stderr, "[ShieldTier] BLOCKED STUN/TURN: %s\n", url.c_str());
        return true;
    }

    // Block DNS-over-HTTPS providers (prevents DNS monitoring bypass)
    if (!host.empty() && NetworkPolicy::is_doh_provider(host)) {
        fprintf(stderr, "[ShieldTier] BLOCKED DoH provider: %s\n", host.c_str());
        return true;
    }

    // Block localhost hostname (supplements IP-based localhost blocking)
    if (!host.empty() && NetworkPolicy::is_localhost(host)) {
        fprintf(stderr, "[ShieldTier] BLOCKED localhost: %s\n", host.c_str());
        return true;
    }

    // Apply domain-level policy rules (malware C2, ads, tracking)
    if (!network_policy_.should_allow(url)) {
        fprintf(stderr, "[ShieldTier] BLOCKED by network policy: %s\n", url.c_str());
        return true;
    }

    if (message_router_ && browser->GetIdentifier() == ui_browser_id_) {
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
        TerminationStatus status,
        int error_code,
        const CefString& error_string) {
    fprintf(stderr, "[ShieldTier] RENDERER TERMINATED: status=%d code=%d msg=%s\n",
            status, error_code, error_string.ToString().c_str());
    if (message_router_ && browser->GetIdentifier() == ui_browser_id_) {
        message_router_->OnRenderProcessTerminated(browser);
    }
}

CefRefPtr<CefResourceRequestHandler> RequestHandler::GetResourceRequestHandler(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> /*frame*/,
    CefRefPtr<CefRequest> request,
    bool /*is_navigation*/,
    bool /*is_download*/,
    const CefString& /*request_initiator*/,
    bool& /*disable_default_handling*/) {
    // Track request start time for content browser requests
    if (browser->GetIdentifier() != ui_browser_id_) {
        std::string url = request->GetURL().ToString();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        std::lock_guard<std::mutex> lock(timing_mutex_);
        request_start_times_[url] = now_ms;
    }
    return this;
}

CefRefPtr<CefResponseFilter> RequestHandler::GetResourceResponseFilter(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> /*frame*/,
    CefRefPtr<CefRequest> request,
    CefRefPtr<CefResponse> response) {

    // Skip UI browser — only capture from content browser
    if (browser->GetIdentifier() == ui_browser_id_) return nullptr;

    if (!is_download_response(request, response)) {
        // Attach body capture filter for text-based responses when capturing
        std::string url = request->GetURL().ToString();
        std::string mime = response->GetMimeType().ToString();
        int browser_id = browser->GetIdentifier();

        if (capture_manager_ && capture_manager_->is_capturing(browser_id) &&
            is_text_mime(mime)) {
            auto* self = this;
            BodyCaptureCallback on_body = [self, url](
                std::string /*cb_url*/, std::string body) {
                std::lock_guard<std::mutex> lock(self->body_mutex_);
                self->captured_bodies_[url] = std::move(body);
            };
            return new ResponseBodyCaptureFilter(url, mime, std::move(on_body));
        }
        return nullptr;
    }

    std::string url = request->GetURL().ToString();
    std::string mime = response->GetMimeType().ToString();
    fprintf(stderr, "[filter] Attaching download capture: %s (mime=%s)\n",
            url.c_str(), mime.c_str());

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
        fprintf(stderr, "[filter] Download captured: sha256=%s file=%s size=%zu\n",
                sha256.c_str(), filename.c_str(), file_size);

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

void RequestHandler::OnResourceLoadComplete(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> /*frame*/,
        CefRefPtr<CefRequest> request,
        CefRefPtr<CefResponse> response,
        URLRequestStatus /*status*/,
        int64_t received_content_length) {
    // Skip UI browser resources (shieldtier://app/ assets)
    if (browser->GetIdentifier() == ui_browser_id_) return;

    std::string url = request->GetURL().ToString();
    // Skip internal schemes
    if (url.compare(0, 13, "shieldtier://") == 0 ||
        url.compare(0, 9, "devtools:") == 0 ||
        url.compare(0, 6, "about:") == 0) return;

    std::string method = request->GetMethod().ToString();
    int status_code = response ? response->GetStatus() : 0;
    std::string status_text = response ? response->GetStatusText().ToString() : "";
    std::string mime = response ? response->GetMimeType().ToString() : "";

    // Map CEF resource type enum to Chrome DevTools-style string
    std::string resource_type;
    switch (request->GetResourceType()) {
        case RT_MAIN_FRAME:
        case RT_SUB_FRAME:
            resource_type = "Document"; break;
        case RT_STYLESHEET:
            resource_type = "Stylesheet"; break;
        case RT_SCRIPT:
            resource_type = "Script"; break;
        case RT_IMAGE:
        case RT_FAVICON:
            resource_type = "Image"; break;
        case RT_FONT_RESOURCE:
            resource_type = "Font"; break;
        case RT_MEDIA:
            resource_type = "Media"; break;
        case RT_XHR:
            resource_type = "XHR"; break;
        default:
            resource_type = "Other"; break;
    }

    // Collect response headers as HAR-format array
    json resp_header_arr = json::array();
    if (response) {
        CefResponse::HeaderMap hm;
        response->GetHeaderMap(hm);
        for (auto& [k, v] : hm) {
            resp_header_arr.push_back({{"name", k.ToString()}, {"value", v.ToString()}});
        }
    }

    // Collect request headers
    json req_header_arr = json::array();
    {
        CefRequest::HeaderMap hm;
        request->GetHeaderMap(hm);
        for (auto& [k, v] : hm) {
            req_header_arr.push_back({{"name", k.ToString()}, {"value", v.ToString()}});
        }
    }

    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    int browser_id = browser->GetIdentifier();

    // Retrieve captured response body (if any)
    std::string response_body;
    {
        std::lock_guard<std::mutex> lock(body_mutex_);
        auto bit = captured_bodies_.find(url);
        if (bit != captured_bodies_.end()) {
            response_body = std::move(bit->second);
            captured_bodies_.erase(bit);
        }
    }

    // Record into CaptureManager (if capturing)
    if (capture_manager_) {
        CapturedRequest cap;
        cap.method = method;
        cap.url = url;
        cap.status_code = status_code;
        cap.response_size = received_content_length;
        cap.mime_type = mime;
        cap.timestamp = ms;
        cap.response_body = response_body;
        capture_manager_->record_request(browser_id, cap);
    }

    // Always push to event bridge for live network panel (HAR entry format)
    if (event_bridge_) {
        // Generate ISO 8601 timestamp
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char iso_buf[64];
        std::strftime(iso_buf, sizeof(iso_buf), "%Y-%m-%dT%H:%M:%S", std::gmtime(&t));
        std::string iso_time = std::string(iso_buf) + "." +
            std::to_string(ms % 1000) + "Z";

        // Build a requestId from timestamp + url hash
        std::string request_id = std::to_string(ms) + "-" +
            std::to_string(std::hash<std::string>{}(url) & 0xFFFFFF);

        // Calculate total time from tracked start time
        double total_time = 0;
        {
            std::lock_guard<std::mutex> lock(timing_mutex_);
            auto it = request_start_times_.find(url);
            if (it != request_start_times_.end()) {
                auto now_ms_steady = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                total_time = static_cast<double>(now_ms_steady - it->second);
                request_start_times_.erase(it);
            }
        }

        // Parse query string from URL
        json query_arr = json::array();
        auto qpos = url.find('?');
        if (qpos != std::string::npos) {
            std::string qs = url.substr(qpos + 1);
            // Remove fragment
            auto fpos = qs.find('#');
            if (fpos != std::string::npos) qs = qs.substr(0, fpos);
            // Split by &
            size_t start = 0;
            while (start < qs.size()) {
                auto amp = qs.find('&', start);
                std::string pair = (amp == std::string::npos)
                    ? qs.substr(start) : qs.substr(start, amp - start);
                if (!pair.empty()) {
                    auto eq = pair.find('=');
                    if (eq != std::string::npos) {
                        query_arr.push_back({
                            {"name", pair.substr(0, eq)},
                            {"value", pair.substr(eq + 1)}
                        });
                    } else {
                        query_arr.push_back({{"name", pair}, {"value", ""}});
                    }
                }
                start = (amp == std::string::npos) ? qs.size() : amp + 1;
            }
        }

        // Capture POST data from request (text-safe content only)
        json post_data = nullptr;
        CefRefPtr<CefPostData> pd = request->GetPostData();
        if (pd.get() && pd->GetElementCount() > 0) {
            // Determine MIME from Content-Type header first
            std::string post_mime;
            {
                CefRequest::HeaderMap hm2;
                request->GetHeaderMap(hm2);
                for (auto& [k2, v2] : hm2) {
                    std::string key_lower = k2.ToString();
                    for (auto& ch : key_lower) ch = static_cast<char>(tolower(ch));
                    if (key_lower == "content-type") {
                        post_mime = v2.ToString();
                        break;
                    }
                }
            }

            // Only capture text-based POST bodies (not binary uploads)
            bool is_text = post_mime.empty() ||
                post_mime.find("text/") != std::string::npos ||
                post_mime.find("json") != std::string::npos ||
                post_mime.find("xml") != std::string::npos ||
                post_mime.find("form-urlencoded") != std::string::npos ||
                post_mime.find("javascript") != std::string::npos;

            if (is_text) {
                CefPostData::ElementVector elements;
                pd->GetElements(elements);
                std::string body_text;
                for (auto& elem : elements) {
                    if (elem->GetType() == PDE_TYPE_BYTES) {
                        size_t sz = elem->GetBytesCount();
                        if (sz > 0 && sz <= 512 * 1024) { // Cap at 512KB for text
                            std::vector<char> buf(sz);
                            elem->GetBytes(sz, buf.data());
                            body_text.append(buf.data(), sz);
                        }
                    }
                }
                // Validate UTF-8 — skip if binary
                bool valid_utf8 = true;
                for (size_t i = 0; i < body_text.size(); ++i) {
                    unsigned char c = static_cast<unsigned char>(body_text[i]);
                    if (c == 0) { valid_utf8 = false; break; }
                    if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
                        valid_utf8 = false; break;
                    }
                }
                if (valid_utf8 && !body_text.empty()) {
                    post_data = {
                        {"mimeType", post_mime},
                        {"text", body_text}
                    };
                }
            }
        }

        json har_entry = {
            {"requestId", request_id},
            {"startedDateTime", iso_time},
            {"time", total_time},
            {"request", {
                {"method", method},
                {"url", url},
                {"httpVersion", "HTTP/1.1"},
                {"headers", req_header_arr},
                {"queryString", query_arr},
                {"headersSize", -1},
                {"bodySize", post_data.is_null() ? -1 : static_cast<int>(post_data["text"].get<std::string>().size())},
            }},
            {"response", {
                {"status", status_code},
                {"statusText", status_text},
                {"httpVersion", "HTTP/1.1"},
                {"headers", resp_header_arr},
                {"content", [&]() {
                    json content = {
                        {"size", received_content_length},
                        {"mimeType", mime},
                    };
                    if (!response_body.empty()) {
                        content["text"] = response_body;
                    }
                    return content;
                }()},
                {"headersSize", -1},
                {"bodySize", received_content_length},
            }},
            {"timings", {
                {"blocked", 0},
                {"dns", 0},
                {"connect", 0},
                {"ssl", 0},
                {"send", 0},
                {"wait", total_time > 0 ? total_time : 0},
                {"receive", 0},
            }},
        };

        // Add resourceType
        har_entry["resourceType"] = resource_type;

        // Add postData if present
        if (!post_data.is_null()) {
            har_entry["request"]["postData"] = post_data;
        }

        event_bridge_->push_capture_update(har_entry);

        // Phase 2b: Check captured request against threat feeds (match V1's checkHAREntry)
        if (threat_feed_manager_) {
            std::string host = extract_host(url);
            bool is_threat = false;
            std::string threat_type;
            if (!host.empty() && threat_feed_manager_->is_known_threat("domain", host)) {
                is_threat = true;
                threat_type = "domain";
            }
            if (!is_threat && threat_feed_manager_->is_known_threat("url", url)) {
                is_threat = true;
                threat_type = "url";
            }
            if (is_threat) {
                auto indicators = threat_feed_manager_->lookup(threat_type,
                    threat_type == "domain" ? host : url);
                json match = {
                    {"url", url},
                    {"matchType", threat_type},
                    {"matchValue", threat_type == "domain" ? host : url},
                    {"indicators", json::array()},
                };
                for (const auto& ind : indicators) {
                    match["indicators"].push_back({
                        {"type", ind.type}, {"value", ind.value},
                        {"source", ind.source}, {"description", ind.description},
                    });
                }
                event_bridge_->push("threatfeed_match", match);
            }
        }

        // Phase 2c: Feed response bodies to content analyzer (match V1's analyzeBody)
        if (content_analyzer_ && !response_body.empty() &&
            (mime.find("text/html") != std::string::npos ||
             mime.find("javascript") != std::string::npos)) {
            FileBuffer content_fb;
            content_fb.data.assign(response_body.begin(), response_body.end());
            content_fb.filename = url;
            content_fb.mime_type = mime;
            auto result = content_analyzer_->analyze(content_fb);
            if (result.ok() && !result.value().findings.empty()) {
                for (const auto& f : result.value().findings) {
                    json finding = {
                        {"url", url},
                        {"title", f.title},
                        {"description", f.description},
                        {"severity", f.severity},
                        {"engine", f.engine},
                        {"metadata", f.metadata},
                    };
                    event_bridge_->push("content_finding", finding);
                }
            }
        }
    }
}

}  // namespace shieldtier
