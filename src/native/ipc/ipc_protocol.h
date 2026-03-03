#pragma once

#include <string>

#include "common/json.h"

namespace shieldtier::ipc {

inline constexpr const char* kActionNavigate = "navigate";
inline constexpr const char* kActionGetTabs = "get_tabs";
inline constexpr const char* kActionCloseTab = "close_tab";
inline constexpr const char* kActionAnalyzeDownload = "analyze_download";
inline constexpr const char* kActionGetAnalysisResult = "get_analysis_result";

struct IpcRequest {
    std::string action;
    json payload;
};

struct IpcResponse {
    bool success;
    json data;
    std::string error;
};

inline json make_success(json data = json::object()) {
    return json{{"success", true}, {"data", data}};
}

inline json make_error(const std::string& msg) {
    return json{{"success", false}, {"error", msg}, {"data", json::object()}};
}

inline IpcRequest parse_request(const std::string& raw) {
    json parsed = parse_json_safe(raw);
    IpcRequest req;
    req.action = parsed.value("action", "");
    req.payload = parsed.value("payload", json::object());
    return req;
}

}  // namespace shieldtier::ipc
