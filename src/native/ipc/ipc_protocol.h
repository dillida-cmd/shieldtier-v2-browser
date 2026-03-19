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
inline constexpr const char* kActionWsbFocusWindow = "wsb_focus_window";
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

inline constexpr const char* kActionAuthLogin = "auth_login";
inline constexpr const char* kActionAuthRegister = "auth_register";
inline constexpr const char* kActionAuthLogout = "auth_logout";
inline constexpr const char* kActionAuthGetUser = "auth_get_user";
inline constexpr const char* kActionAuthRestoreSession = "auth_restore_session";
inline constexpr const char* kActionAuthChangePassword = "auth_change_password";
inline constexpr const char* kActionAuthResendVerification = "auth_resend_verification";
inline constexpr const char* kActionAuthRefreshProfile = "auth_refresh_profile";
inline constexpr const char* kActionAuthUpdateProfile = "auth_update_profile";
inline constexpr const char* kActionAuthSyncCases = "auth_sync_cases";
inline constexpr const char* kActionAuthGetCases = "auth_get_cases";
inline constexpr const char* kActionAuthSetSyncKey = "auth_set_sync_key";

inline constexpr const char* kActionUploadFiles = "upload_files";
inline constexpr const char* kActionTakeScreenshot = "take_screenshot";
inline constexpr const char* kActionTakeDomSnapshot = "take_dom_snapshot";

inline constexpr const char* kActionSetContentBounds = "set_content_bounds";
inline constexpr const char* kActionHideContentBrowser = "hide_content_browser";
inline constexpr const char* kActionSetZoom = "set_zoom";
inline constexpr const char* kActionGetZoom = "get_zoom";
inline constexpr const char* kActionGetNavState = "get_nav_state";
inline constexpr const char* kActionAnalyzeNow = "analyze_now";

// Config
inline constexpr const char* kActionCheckWhitelist = "check_whitelist";

// YARA
inline constexpr const char* kActionYaraGetRules = "yara_get_rules";
inline constexpr const char* kActionYaraGetRule = "yara_get_rule";
inline constexpr const char* kActionYaraAddRule = "yara_add_rule";
inline constexpr const char* kActionYaraUpdateRule = "yara_update_rule";
inline constexpr const char* kActionYaraDeleteRule = "yara_delete_rule";
inline constexpr const char* kActionYaraImportRules = "yara_import_rules";
inline constexpr const char* kActionYaraExportRules = "yara_export_rules";
inline constexpr const char* kActionYaraGetPacks = "yara_get_packs";
inline constexpr const char* kActionYaraTogglePack = "yara_toggle_pack";
inline constexpr const char* kActionYaraScanFile = "yara_scan_file";
inline constexpr const char* kActionYaraScanContent = "yara_scan_content";
inline constexpr const char* kActionYaraGetResults = "yara_get_results";

// File Analysis
inline constexpr const char* kActionDeleteFile = "delete_file";
inline constexpr const char* kActionSubmitArchivePassword = "submit_archive_password";
inline constexpr const char* kActionSkipArchivePassword = "skip_archive_password";

// Email
inline constexpr const char* kActionGetEmails = "get_emails";
inline constexpr const char* kActionGetEmail = "get_email";
inline constexpr const char* kActionOpenEmailFile = "open_email_file";

// Chat (new)
inline constexpr const char* kActionChatRemoveContact = "chat_remove_contact";
inline constexpr const char* kActionChatUpdateContact = "chat_update_contact";
inline constexpr const char* kActionChatGetConversations = "chat_get_conversations";
inline constexpr const char* kActionChatLookupUser = "chat_lookup_user";
inline constexpr const char* kActionChatAckOnboarding = "chat_ack_onboarding";
inline constexpr const char* kActionChatGetRequests = "chat_get_requests";

// Threat Feed
inline constexpr const char* kActionThreatfeedAdd = "threatfeed_add";
inline constexpr const char* kActionThreatfeedUpdate = "threatfeed_update";
inline constexpr const char* kActionThreatfeedDelete = "threatfeed_delete";
inline constexpr const char* kActionThreatfeedToggle = "threatfeed_toggle";
inline constexpr const char* kActionThreatfeedDiscover = "threatfeed_discover";
inline constexpr const char* kActionThreatfeedCollections = "threatfeed_collections";
inline constexpr const char* kActionThreatfeedSync = "threatfeed_sync";
inline constexpr const char* kActionThreatfeedSyncAll = "threatfeed_sync_all";
inline constexpr const char* kActionThreatfeedMatches = "threatfeed_matches";
inline constexpr const char* kActionThreatfeedImportCsv = "threatfeed_import_csv";
inline constexpr const char* kActionThreatfeedImportStix = "threatfeed_import_stix";
inline constexpr const char* kActionThreatfeedStats = "threatfeed_stats";

// VM
inline constexpr const char* kActionVmGetStatus = "vm_get_status";
inline constexpr const char* kActionVmInstall = "vm_install";
inline constexpr const char* kActionVmListImages = "vm_list_images";
inline constexpr const char* kActionVmDownloadImage = "vm_download_image";
inline constexpr const char* kActionVmGetInstances = "vm_get_instances";
inline constexpr const char* kActionVmGetResult = "vm_get_result";
inline constexpr const char* kActionVmHasSnapshot = "vm_has_snapshot";
inline constexpr const char* kActionVmPrepareSnapshot = "vm_prepare_snapshot";
inline constexpr const char* kActionVmGetCaCert = "vm_get_ca_cert";
inline constexpr const char* kActionVmBuildAgent = "vm_build_agent";
inline constexpr const char* kActionVmGetAgentStatus = "vm_get_agent_status";

// Log Analysis
inline constexpr const char* kActionGetLogResult = "get_log_result";
inline constexpr const char* kActionDeleteLogResult = "delete_log_result";
inline constexpr const char* kActionGetLogFormats = "get_log_formats";
inline constexpr const char* kActionOpenLogFile = "open_log_file";

// Capture
inline constexpr const char* kActionGetCaptureStatus = "get_capture_status";
inline constexpr const char* kActionGetScreenshots = "get_screenshots";
inline constexpr const char* kActionGetDomSnapshots = "get_dom_snapshots";

// Content Analysis
inline constexpr const char* kActionGetContentFindings = "get_content_findings";

// Proxy
inline constexpr const char* kActionTestProxy = "test_proxy";

// Report
inline constexpr const char* kActionPreviewReport = "preview_report";
inline constexpr const char* kActionSaveReport = "save_report";

// Enrichment
inline constexpr const char* kActionEnrichmentQuery = "enrichment_query";
inline constexpr const char* kActionEnrichmentGetResults = "enrichment_get_results";

// Sessions (main-process state)
inline constexpr const char* kActionSessionCreate = "session_create";
inline constexpr const char* kActionSessionDestroy = "session_destroy";
inline constexpr const char* kActionSessionList = "session_list";

// Cloud Sandbox
inline constexpr const char* kActionCloudSandboxSubmit = "cloud_sandbox_submit";
inline constexpr const char* kActionCloudSandboxPoll = "cloud_sandbox_poll";

// URL Chain Investigation
inline constexpr const char* kActionInvestigateUrl = "investigate_url";
inline constexpr const char* kActionGetUrlChains = "get_url_chains";

// Document Preview
inline constexpr const char* kActionGetFilePreview = "get_file_preview";

// App Info / Update / Feedback
inline constexpr const char* kActionGetAppInfo = "get_app_info";
inline constexpr const char* kActionCheckUpdate = "check_update";
inline constexpr const char* kActionSubmitFeedback = "submit_feedback";

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
