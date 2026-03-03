#include "capture/capture_manager.h"

namespace shieldtier {
namespace {

constexpr size_t kMaxRequestsPerSession = 10000;

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
    std::lock_guard<std::mutex> lock(mutex_);

    if (active_.count(browser_id) == 0) return;

    auto& requests = captures_[browser_id];
    if (requests.size() >= kMaxRequestsPerSession) return;

    requests.push_back(req);
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

}  // namespace shieldtier
