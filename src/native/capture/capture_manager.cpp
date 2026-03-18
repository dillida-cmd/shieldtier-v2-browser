#include "capture/capture_manager.h"

#include <algorithm>
#include <cctype>
#include <regex>

namespace shieldtier {
namespace {

constexpr size_t kMaxRequestsPerSession = 10000;

// RFC1918 and other private IP ranges
bool is_private_ip(const std::string& ip) {
    // Simple prefix checks matching V1's PRIVATE_IP_RX patterns
    if (ip.compare(0, 4, "127.") == 0) return true;
    if (ip.compare(0, 3, "10.") == 0) return true;
    if (ip.compare(0, 8, "192.168.") == 0) return true;
    if (ip.compare(0, 8, "169.254.") == 0) return true;
    if (ip.compare(0, 2, "0.") == 0) return true;
    if (ip == "::1" || ip.compare(0, 5, "fe80:") == 0 ||
        ip.compare(0, 5, "fc00:") == 0 || ip.compare(0, 2, "fd") == 0) {
        return true;
    }
    // 172.16.0.0/12
    if (ip.compare(0, 4, "172.") == 0) {
        auto dot = ip.find('.', 4);
        if (dot != std::string::npos) {
            int second = std::atoi(ip.c_str() + 4);
            if (second >= 16 && second <= 31) return true;
        }
    }
    return false;
}

bool is_valid_ipv4(const std::string& s) {
    static const std::regex ipv4_re(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    if (!std::regex_match(s, ipv4_re)) return false;
    // Validate octets
    int start = 0;
    for (int i = 0; i < 4; ++i) {
        auto dot = s.find('.', start);
        int octet = std::atoi(s.c_str() + start);
        if (octet < 0 || octet > 255) return false;
        start = (dot == std::string::npos) ? static_cast<int>(s.size()) : static_cast<int>(dot) + 1;
    }
    return true;
}

std::string extract_host_from_url(const std::string& url) {
    auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) return {};
    auto host_start = scheme_end + 3;
    auto host_end = url.find_first_of(":/?#", host_start);
    size_t len = (host_end == std::string::npos) ? std::string::npos
                                                  : host_end - host_start;
    return url.substr(host_start, len);
}

}  // namespace

CaptureManager::CaptureManager() = default;

void CaptureManager::start_capture(int browser_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    active_.insert(browser_id);
    captures_[browser_id] = {};
}

void CaptureManager::stop_capture(int browser_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    active_.erase(browser_id);
}

void CaptureManager::record_request(int browser_id,
                                      const CapturedRequest& req) {
    std::vector<ExtractedIOC> iocs;
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (active_.count(browser_id) == 0) return;

        auto& requests = captures_[browser_id];
        if (requests.size() >= kMaxRequestsPerSession) return;

        requests.push_back(req);

        // Extract IOCs from the request URL (C++ side, matches V1 pipeline)
        iocs = extract_iocs(req.url);
    }

    // Fire IOC callback outside mutex to avoid deadlocks
    if (!iocs.empty() && ioc_callback_) {
        ioc_callback_(iocs);
    }
}

std::vector<CapturedRequest> CaptureManager::get_requests(
    int browser_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = captures_.find(browser_id);
    if (it == captures_.end()) return {};
    return it->second;
}

bool CaptureManager::is_capturing(int browser_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_.count(browser_id) > 0;
}

void CaptureManager::clear(int browser_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    captures_.erase(browser_id);
    active_.erase(browser_id);
}

void CaptureManager::store_response_body(int browser_id,
                                           const std::string& url,
                                           std::string body) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = captures_.find(browser_id);
    if (it == captures_.end()) return;

    // Walk backwards — most recent match is most likely
    auto& requests = it->second;
    for (auto rit = requests.rbegin(); rit != requests.rend(); ++rit) {
        if (rit->url == url) {
            rit->response_body = std::move(body);
            return;
        }
    }
}

void CaptureManager::set_ioc_callback(IOCCallback cb) {
    ioc_callback_ = std::move(cb);
}

std::vector<ExtractedIOC> CaptureManager::extract_iocs(
    const std::string& url, const std::string& server_ip) {
    std::vector<ExtractedIOC> iocs;

    // Extract hostname from URL
    std::string host = extract_host_from_url(url);
    if (host.empty()) return iocs;

    std::string host_lower = host;
    for (auto& c : host_lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    // Check if hostname is an IP address
    if (is_valid_ipv4(host_lower)) {
        if (!is_private_ip(host_lower) && seen_iocs_.insert(host_lower).second) {
            iocs.push_back({host, "ip", "network_traffic"});
        }
    } else {
        // It's a domain
        if (seen_iocs_.insert(host_lower).second) {
            iocs.push_back({host_lower, "domain", "network_traffic"});
        }
        // Register full URL as separate IOC (skip safe/common domains)
        if (seen_iocs_.insert(url).second) {
            iocs.push_back({url, "url", "network_traffic"});
        }
    }

    // Register server IP if provided and not private
    if (!server_ip.empty() && is_valid_ipv4(server_ip) &&
        !is_private_ip(server_ip)) {
        if (seen_iocs_.insert(server_ip).second) {
            iocs.push_back({server_ip, "ip", "server_address"});
        }
    }

    return iocs;
}

}  // namespace shieldtier
