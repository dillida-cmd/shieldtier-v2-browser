#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common/json.h"

namespace shieldtier {

struct CapturedRequest {
    std::string method;
    std::string url;
    std::unordered_map<std::string, std::string> request_headers;
    std::unordered_map<std::string, std::string> response_headers;
    int status_code;
    int64_t request_size;
    int64_t response_size;
    double duration_ms;
    int64_t timestamp;
    std::string mime_type;
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

private:
    std::unordered_map<int, std::vector<CapturedRequest>> captures_;
    std::unordered_set<int> active_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
