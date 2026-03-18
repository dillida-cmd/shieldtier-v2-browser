#pragma once

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common/json.h"

namespace shieldtier {

/// IOC extracted from network traffic.
struct ExtractedIOC {
    std::string value;
    std::string type;     // "ip", "domain", "url"
    std::string source;   // "network_traffic", "server_address"
};

struct CapturedRequest {
    std::string method;
    std::string url;
    std::unordered_map<std::string, std::string> request_headers;
    std::unordered_map<std::string, std::string> response_headers;
    int status_code = 0;
    int64_t request_size = 0;
    int64_t response_size = 0;
    double duration_ms = 0.0;
    int64_t timestamp = 0;
    std::string mime_type;
    std::string response_body;
};

class CaptureManager {
public:
    CaptureManager();

    void start_capture(int browser_id);
    void stop_capture(int browser_id);
    void record_request(int browser_id, const CapturedRequest& req);

    std::vector<CapturedRequest> get_requests(int browser_id) const;
    bool is_capturing(int browser_id) const;
    void clear(int browser_id);
    void store_response_body(int browser_id, const std::string& url, std::string body);

    /// Extract IOCs (domains, IPs, URLs) from a captured request URL.
    std::vector<ExtractedIOC> extract_iocs(const std::string& url,
                                            const std::string& server_ip = "");

    /// Set a callback to be invoked when new IOCs are extracted during capture.
    using IOCCallback = std::function<void(const std::vector<ExtractedIOC>&)>;
    void set_ioc_callback(IOCCallback cb);

private:
    std::unordered_map<int, std::vector<CapturedRequest>> captures_;
    std::unordered_set<int> active_;
    mutable std::mutex mutex_;

    IOCCallback ioc_callback_;
    std::unordered_set<std::string> seen_iocs_;  // dedup within session
};

}  // namespace shieldtier
