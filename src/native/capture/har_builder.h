#pragma once

#include <string>
#include <vector>

#include "capture/capture_manager.h"
#include "common/json.h"

namespace shieldtier {

class HarBuilder {
public:
    HarBuilder();

    json build(const std::vector<CapturedRequest>& requests) const;
    std::string build_string(const std::vector<CapturedRequest>& requests) const;

private:
    json build_entry(const CapturedRequest& req) const;
    json build_headers(
        const std::unordered_map<std::string, std::string>& headers) const;
    std::string format_timestamp(int64_t epoch_ms) const;
};

}  // namespace shieldtier
