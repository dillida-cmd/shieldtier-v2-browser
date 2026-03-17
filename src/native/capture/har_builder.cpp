#include "capture/har_builder.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace shieldtier {

HarBuilder::HarBuilder() = default;

json HarBuilder::build(const std::vector<CapturedRequest>& requests) const {
    json entries = json::array();
    for (const auto& req : requests) {
        entries.push_back(build_entry(req));
    }

    return {
        {"log", {
            {"version", "1.2"},
            {"creator", {
                {"name", "ShieldTier"},
                {"version", "2.0"}
            }},
            {"entries", std::move(entries)}
        }}
    };
}

std::string HarBuilder::build_string(
    const std::vector<CapturedRequest>& requests) const {
    return build(requests).dump(2);
}

json HarBuilder::build_entry(const CapturedRequest& req) const {
    return {
        {"startedDateTime", format_timestamp(req.timestamp)},
        {"time", req.duration_ms},
        {"request", {
            {"method", req.method},
            {"url", req.url},
            {"httpVersion", "HTTP/1.1"},
            {"headers", build_headers(req.request_headers)},
            {"headerSize", -1},
            {"bodySize", req.request_size}
        }},
        {"response", {
            {"status", req.status_code},
            {"statusText", ""},
            {"httpVersion", "HTTP/1.1"},
            {"headers", build_headers(req.response_headers)},
            {"content", {
                {"size", req.response_size},
                {"mimeType", req.mime_type}
            }},
            {"headerSize", -1},
            {"bodySize", req.response_size}
        }},
        {"cache", json::object()},
        {"timings", {
            {"send", 0},
            {"wait", req.duration_ms},
            {"receive", 0}
        }}
    };
}

json HarBuilder::build_headers(
    const std::unordered_map<std::string, std::string>& headers) const {
    json arr = json::array();
    for (const auto& [name, value] : headers) {
        arr.push_back({{"name", name}, {"value", value}});
    }
    return arr;
}

std::string HarBuilder::format_timestamp(int64_t epoch_ms) const {
    if (epoch_ms < 0) epoch_ms = 0;
    auto seconds = static_cast<time_t>(epoch_ms / 1000);
    int millis = static_cast<int>(epoch_ms % 1000);

    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &seconds);
#else
    gmtime_r(&seconds, &utc);
#endif

    std::ostringstream ss;
    ss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << millis << 'Z';
    return ss.str();
}

}  // namespace shieldtier
