#pragma once

#include <string>

#include "common/json.h"

namespace shieldtier::ipc {

inline constexpr const char* kActionNavigate = "navigate";
inline constexpr const char* kActionGetTabs = "get_tabs";
inline constexpr const char* kActionCloseTab = "close_tab";
inline constexpr const char* kActionAnalyzeDownload = "analyze_download";
inline constexpr const char* kActionGetAnalysisResult = "get_analysis_result";
inline constexpr const char* kActionGetConfig = "get_config";
inline constexpr const char* kActionSetConfig = "set_config";
inline constexpr const char* kActionExportReport = "export_report";
inline constexpr const char* kActionGetThreatFeeds = "get_threat_feeds";
inline constexpr const char* kActionStartCapture = "start_capture";
inline constexpr const char* kActionStopCapture = "stop_capture";
inline constexpr const char* kActionGetCapture = "get_capture";
inline constexpr const char* kActionNavBack = "nav_back";
inline constexpr const char* kActionNavForward = "nav_forward";
inline constexpr const char* kActionNavReload = "nav_reload";
inline constexpr const char* kActionNavStop = "nav_stop";
inline constexpr const char* kActionStartVm = "start_vm";
inline constexpr const char* kActionStopVm = "stop_vm";
inline constexpr const char* kActionSubmitSampleToVm = "submit_sample_to_vm";
inline constexpr const char* kActionAnalyzeEmail = "analyze_email";
inline constexpr const char* kActionAnalyzeLogs = "analyze_logs";
inline constexpr const char* kActionGetLogResults = "get_log_results";

inline constexpr const char* kActionChatGetIdentity = "chat_get_identity";
inline constexpr const char* kActionChatGetContacts = "chat_get_contacts";
inline constexpr const char* kActionChatAddContact = "chat_add_contact";
inline constexpr const char* kActionChatApproveContact = "chat_approve_contact";
inline constexpr const char* kActionChatRejectContact = "chat_reject_contact";
inline constexpr const char* kActionChatGetMessages = "chat_get_messages";
inline constexpr const char* kActionChatSendMessage = "chat_send_message";
inline constexpr const char* kActionChatMarkRead = "chat_mark_read";
inline constexpr const char* kActionChatGetStatus = "chat_get_status";
inline constexpr const char* kActionChatSetPresence = "chat_set_presence";

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
