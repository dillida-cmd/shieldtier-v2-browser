#include "ipc/message_handler.h"

#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <thread>

#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif

#include "app/shieldtier_client.h"
#include "analysis/fileanalysis/file_analyzer.h"
#include "browser/navigation.h"
#include "chat/shieldcrypt.h"
#include "config/paths.h"
#include "vm/vm_scoring.h"
#include "vm/windows_sandbox.h"

namespace shieldtier {

// Dev auth bypass — DEBUG BUILDS ONLY.
// In release builds (NDEBUG defined), this is always false.
static bool is_dev_auth_enabled() {
#ifdef NDEBUG
    return false;  // NEVER allow dev auth in release builds
#else
    static int cached = -1;
    if (cached < 0) {
        const char* val = std::getenv("SHIELDTIER_DEV_AUTH");
        cached = (val && std::string(val) == "1") ? 1 : 0;
        if (cached) {
            fprintf(stderr, "[SECURITY WARNING] Dev auth bypass is active — DO NOT ship this build.\n");
        }
    }
    return cached == 1;
#endif
}

#ifndef NDEBUG
static json make_dev_user() {
    return json{
        {"id", "dev-local-user"},
        {"email", "dev@shieldtier.local"},
        {"analystName", "Dev Analyst"},
        {"tier", "enterprise"},
        {"emailVerified", true},
        {"avatar", "shield"},
    };
}
#endif

MessageHandler::MessageHandler(SessionManager* session_manager)
    : session_manager_(session_manager),
      yara_engine_(std::make_unique<YaraEngine>()),
      file_analyzer_(std::make_unique<FileAnalyzer>()),
      enrichment_manager_(std::make_unique<EnrichmentManager>(EnrichmentConfig{})),
      scoring_engine_(std::make_unique<ScoringEngine>()),
      sandbox_engine_(std::make_unique<SandboxEngine>()),
      advanced_engine_(std::make_unique<AdvancedEngine>()),
      email_analyzer_(std::make_unique<EmailAnalyzer>()),
      content_analyzer_(std::make_unique<ContentAnalyzer>()),
      log_manager_(std::make_unique<LogManager>()),
      log_analysis_engine_(std::make_unique<LogAnalysisEngine>()),
      threat_feed_manager_(std::make_unique<ThreatFeedManager>()),
      capture_manager_(std::make_unique<CaptureManager>()),
      config_store_(std::make_unique<ConfigStore>(paths::get_config_path())),
      export_manager_(std::make_unique<ExportManager>()),
      vm_manager_(std::make_unique<VmManager>(paths::get_data_path() + "/vms")),
      vm_installer_(std::make_unique<VmInstaller>(paths::get_data_path() + "/vms")),
      chat_manager_(std::make_unique<ChatManager>(paths::get_data_path() + "/chat")),
      cloud_sandbox_(std::make_unique<CloudSandboxManager>(CloudSandboxConfig{})),
      windows_sandbox_(std::make_unique<WindowsSandbox>(paths::get_data_path() + "/wsb_sessions")),
      inetsim_server_(std::make_unique<INetSimServer>()),
      auth_http_(std::make_unique<HttpClient>()) {
    chat_manager_->initialize_keys();
    yara_engine_->initialize();
    config_store_->load();
    threat_feed_manager_->update_feeds();
    auth_http_->set_timeout(5);
    auth_http_->set_user_agent("ShieldTier/2.0");
}

MessageHandler::~MessageHandler() {
    // Join worker threads FIRST so they can read results before cleanup.
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        analysis_threads_.clear();  // jthread destructor requests stop and joins
    }

    // NOW stop Windows Sandbox (kills processes + cleans up session dir).
    if (!active_wsb_session_.empty() && windows_sandbox_) {
        fprintf(stderr, "[ShieldTier] Shutting down active sandbox session: %s\n",
                active_wsb_session_.c_str());
        windows_sandbox_->stop(active_wsb_session_);
        active_wsb_session_.clear();
    }
}

bool MessageHandler::OnQuery(CefRefPtr<CefBrowser> browser,
                             CefRefPtr<CefFrame> frame,
                             int64_t /*query_id*/,
                             const CefString& request,
                             bool /*persistent*/,
                             CefRefPtr<Callback> callback) {
    // Security: reject IPC from non-shieldtier:// origins
    if (frame) {
        std::string origin = frame->GetURL().ToString();
        if (origin.compare(0, 13, "shieldtier://") != 0) {
            callback->Failure(403, ipc::make_error("ipc_forbidden").dump());
            return true;
        }
    }

    try {
        auto req = ipc::parse_request(request.ToString());
        fprintf(stderr, "[ShieldTier] IPC: action=%s\n", req.action.c_str());

        // Handle simple actions before the long else-if chain to avoid
        // MSVC C1061 "blocks nested too deeply" compiler limit.
        // Handle actions before the long else-if chain to avoid
        // MSVC C1061 "blocks nested too deeply" compiler limit.
        static const std::unordered_map<std::string, std::function<json(MessageHandler*, const json&)>> early_handlers = {
            {ipc::kActionWsbFocusWindow, [](MessageHandler* h, const json& p) { return h->handle_wsb_focus_window(p); }},
            {ipc::kActionGetAppInfo, [](MessageHandler* h, const json& p) { return h->handle_get_app_info(p); }},
            {ipc::kActionCheckUpdate, [](MessageHandler* h, const json& p) { return h->handle_check_update(p); }},
            {ipc::kActionSubmitFeedback, [](MessageHandler* h, const json& p) { return h->handle_submit_feedback(p); }},
            {ipc::kActionGetFilePreview, [](MessageHandler* h, const json& p) { return h->handle_get_file_preview(p); }},
            {ipc::kActionInvestigateUrl, [](MessageHandler* h, const json& p) { return h->handle_investigate_url(p); }},
            {ipc::kActionGetUrlChains, [](MessageHandler* h, const json& p) { return h->handle_get_url_chains(p); }},
        };
        auto early_it = early_handlers.find(req.action);
        if (early_it != early_handlers.end()) {
            callback->Success(early_it->second(this, req.payload).dump());
            return true;
        }

        json result;
        if (req.action == ipc::kActionNavigate) {
            result = handle_navigate(browser, req.payload);
        } else if (req.action == ipc::kActionGetTabs) {
            result = handle_get_tabs(req.payload);
        } else if (req.action == ipc::kActionCloseTab) {
            result = handle_close_tab(req.payload);
        } else if (req.action == ipc::kActionAnalyzeDownload) {
            result = handle_analyze_download(req.payload);
        } else if (req.action == ipc::kActionGetAnalysisResult) {
            result = handle_get_analysis_result(req.payload);
        } else if (req.action == ipc::kActionGetConfig) {
            result = handle_get_config(req.payload);
        } else if (req.action == ipc::kActionSetConfig) {
            result = handle_set_config(req.payload);
        } else if (req.action == ipc::kActionExportReport) {
            result = handle_export_report(req.payload);
        } else if (req.action == ipc::kActionGetThreatFeeds) {
            result = handle_get_threat_feeds(req.payload);
        } else if (req.action == ipc::kActionStartCapture) {
            result = handle_start_capture(req.payload);
        } else if (req.action == ipc::kActionStopCapture) {
            result = handle_stop_capture(req.payload);
        } else if (req.action == ipc::kActionGetCapture) {
            result = handle_get_capture(req.payload);
        } else if (req.action == ipc::kActionNavBack) {
            result = handle_nav_back(req.payload);
        } else if (req.action == ipc::kActionNavForward) {
            result = handle_nav_forward(req.payload);
        } else if (req.action == ipc::kActionNavReload) {
            result = handle_nav_reload(req.payload);
        } else if (req.action == ipc::kActionNavStop) {
            result = handle_nav_stop(req.payload);
        } else if (req.action == ipc::kActionSetContentBounds) {
            result = handle_set_content_bounds(req.payload);
        } else if (req.action == ipc::kActionHideContentBrowser) {
            result = handle_hide_content_browser(req.payload);
        } else if (req.action == ipc::kActionSetZoom) {
            result = handle_set_zoom(req.payload);
        } else if (req.action == ipc::kActionGetZoom) {
            result = handle_get_zoom(req.payload);
        } else if (req.action == ipc::kActionStartVm) {
            result = handle_start_vm(req.payload);
        } else if (req.action == ipc::kActionStopVm) {
            result = handle_stop_vm(req.payload);
        } else if (req.action == ipc::kActionSubmitSampleToVm) {
            result = handle_submit_sample_to_vm(req.payload);
        } else if (req.action == ipc::kActionAnalyzeEmail) {
            result = handle_analyze_email(req.payload);
        } else if (req.action == ipc::kActionAnalyzeLogs) {
            result = handle_analyze_logs(req.payload);
        } else if (req.action == ipc::kActionGetLogResults) {
            result = handle_get_log_results(req.payload);
        } else if (req.action == ipc::kActionUploadFiles) {
            result = handle_upload_files(req.payload);
        } else if (req.action == ipc::kActionTakeScreenshot) {
            if (!ui_client_) {
                callback->Failure(500, ipc::make_error("no_ui_client").dump());
            } else {
                ui_client_->content_take_screenshot(
                    [callback](const json& r) {
                        callback->Success(ipc::make_success(r).dump());
                    });
            }
            return true;  // deferred — response sent by CDP callback
        } else if (req.action == ipc::kActionTakeDomSnapshot) {
            if (!ui_client_) {
                callback->Failure(500, ipc::make_error("no_ui_client").dump());
            } else {
                ui_client_->content_take_dom_snapshot(
                    [callback](const json& r) {
                        callback->Success(ipc::make_success(r).dump());
                    });
            }
            return true;  // deferred — response sent by CDP callback
        } else if (req.action == ipc::kActionChatGetIdentity) {
            result = handle_chat_get_identity(req.payload);
        } else if (req.action == ipc::kActionChatGetContacts) {
            result = handle_chat_get_contacts(req.payload);
        } else if (req.action == ipc::kActionChatAddContact) {
            result = handle_chat_add_contact(req.payload);
        } else if (req.action == ipc::kActionChatApproveContact) {
            result = handle_chat_approve_contact(req.payload);
        } else if (req.action == ipc::kActionChatRejectContact) {
            result = handle_chat_reject_contact(req.payload);
        } else if (req.action == ipc::kActionChatGetMessages) {
            result = handle_chat_get_messages(req.payload);
        } else if (req.action == ipc::kActionChatSendMessage) {
            result = handle_chat_send_message(req.payload);
        } else if (req.action == ipc::kActionChatMarkRead) {
            result = handle_chat_mark_read(req.payload);
        } else if (req.action == ipc::kActionChatGetStatus) {
            result = handle_chat_get_status(req.payload);
        } else if (req.action == ipc::kActionChatSetPresence) {
            result = handle_chat_set_presence(req.payload);
        } else if (req.action == ipc::kActionAuthLogin) {
            result = handle_auth_login(req.payload);
        } else if (req.action == ipc::kActionAuthRegister) {
            result = handle_auth_register(req.payload);
        } else if (req.action == ipc::kActionAuthLogout) {
            result = handle_auth_logout(req.payload);
        } else if (req.action == ipc::kActionAuthGetUser) {
            result = handle_auth_get_user(req.payload);
        } else if (req.action == ipc::kActionAuthRestoreSession) {
            result = handle_auth_restore_session(req.payload);
        } else if (req.action == ipc::kActionAuthChangePassword) {
            result = handle_auth_change_password(req.payload);
        } else if (req.action == ipc::kActionAuthResendVerification) {
            result = handle_auth_resend_verification(req.payload);
        } else if (req.action == ipc::kActionAuthRefreshProfile) {
            result = handle_auth_refresh_profile(req.payload);
        } else if (req.action == ipc::kActionAuthUpdateProfile) {
            result = handle_auth_update_profile(req.payload);
        } else if (req.action == ipc::kActionAuthSyncCases) {
            result = handle_auth_sync_cases(req.payload);
        } else if (req.action == ipc::kActionAuthGetCases) {
            result = handle_auth_get_cases(req.payload);
        } else if (req.action == ipc::kActionAuthSetSyncKey) {
            result = handle_auth_set_sync_key(req.payload);
        // ── New handlers ──
        } else if (req.action == ipc::kActionGetNavState) {
            result = handle_get_nav_state(req.payload);
        } else if (req.action == ipc::kActionAnalyzeNow) {
            result = handle_analyze_now(req.payload);
        } else if (req.action == ipc::kActionCheckWhitelist) {
            result = handle_check_whitelist(req.payload);
        // YARA
        } else if (req.action == ipc::kActionYaraGetRules) {
            result = handle_yara_get_rules(req.payload);
        } else if (req.action == ipc::kActionYaraGetRule) {
            result = handle_yara_get_rule(req.payload);
        } else if (req.action == ipc::kActionYaraAddRule) {
            result = handle_yara_add_rule(req.payload);
        } else if (req.action == ipc::kActionYaraUpdateRule) {
            result = handle_yara_update_rule(req.payload);
        } else if (req.action == ipc::kActionYaraDeleteRule) {
            result = handle_yara_delete_rule(req.payload);
        } else if (req.action == ipc::kActionYaraImportRules) {
            result = handle_yara_import_rules(req.payload);
        } else if (req.action == ipc::kActionYaraExportRules) {
            result = handle_yara_export_rules(req.payload);
        } else if (req.action == ipc::kActionYaraGetPacks) {
            result = handle_yara_get_packs(req.payload);
        } else if (req.action == ipc::kActionYaraTogglePack) {
            result = handle_yara_toggle_pack(req.payload);
        } else if (req.action == ipc::kActionYaraScanFile) {
            result = handle_yara_scan_file(req.payload);
        } else if (req.action == ipc::kActionYaraScanContent) {
            result = handle_yara_scan_content(req.payload);
        } else if (req.action == ipc::kActionYaraGetResults) {
            result = handle_yara_get_results(req.payload);
        // File Analysis
        } else if (req.action == ipc::kActionDeleteFile) {
            result = handle_delete_file(req.payload);
        } else if (req.action == ipc::kActionSubmitArchivePassword) {
            result = handle_submit_archive_password(req.payload);
        } else if (req.action == ipc::kActionSkipArchivePassword) {
            result = handle_skip_archive_password(req.payload);
        // Email
        } else if (req.action == ipc::kActionGetEmails) {
            result = handle_get_emails(req.payload);
        } else if (req.action == ipc::kActionGetEmail) {
            result = handle_get_email(req.payload);
        } else if (req.action == ipc::kActionOpenEmailFile) {
            result = handle_open_email_file(req.payload);
        // Chat (new)
        } else if (req.action == ipc::kActionChatRemoveContact) {
            result = handle_chat_remove_contact(req.payload);
        } else if (req.action == ipc::kActionChatUpdateContact) {
            result = handle_chat_update_contact(req.payload);
        } else if (req.action == ipc::kActionChatGetConversations) {
            result = handle_chat_get_conversations(req.payload);
        } else if (req.action == ipc::kActionChatLookupUser) {
            result = handle_chat_lookup_user(req.payload);
        } else if (req.action == ipc::kActionChatAckOnboarding) {
            result = handle_chat_ack_onboarding(req.payload);
        } else if (req.action == ipc::kActionChatGetRequests) {
            result = handle_chat_get_requests(req.payload);
        // Threat Feed
        } else if (req.action == ipc::kActionThreatfeedAdd) {
            result = handle_threatfeed_add(req.payload);
        } else if (req.action == ipc::kActionThreatfeedUpdate) {
            result = handle_threatfeed_update(req.payload);
        } else if (req.action == ipc::kActionThreatfeedDelete) {
            result = handle_threatfeed_delete(req.payload);
        } else if (req.action == ipc::kActionThreatfeedToggle) {
            result = handle_threatfeed_toggle(req.payload);
        } else if (req.action == ipc::kActionThreatfeedDiscover) {
            result = handle_threatfeed_discover(req.payload);
        } else if (req.action == ipc::kActionThreatfeedCollections) {
            result = handle_threatfeed_collections(req.payload);
        } else if (req.action == ipc::kActionThreatfeedSync) {
            result = handle_threatfeed_sync(req.payload);
        } else if (req.action == ipc::kActionThreatfeedSyncAll) {
            result = handle_threatfeed_sync_all(req.payload);
        } else if (req.action == ipc::kActionThreatfeedMatches) {
            result = handle_threatfeed_matches(req.payload);
        } else if (req.action == ipc::kActionThreatfeedImportCsv) {
            result = handle_threatfeed_import_csv(req.payload);
        } else if (req.action == ipc::kActionThreatfeedImportStix) {
            result = handle_threatfeed_import_stix(req.payload);
        } else if (req.action == ipc::kActionThreatfeedStats) {
            result = handle_threatfeed_stats(req.payload);
        // VM
        } else if (req.action == ipc::kActionVmGetStatus) {
            result = handle_vm_get_status(req.payload);
        } else if (req.action == ipc::kActionVmInstall) {
            result = handle_vm_install(req.payload);
        } else if (req.action == ipc::kActionVmListImages) {
            result = handle_vm_list_images(req.payload);
        } else if (req.action == ipc::kActionVmDownloadImage) {
            result = handle_vm_download_image(req.payload);
        } else if (req.action == ipc::kActionVmGetInstances) {
            result = handle_vm_get_instances(req.payload);
        } else if (req.action == ipc::kActionVmGetResult) {
            result = handle_vm_get_result(req.payload);
        } else if (req.action == ipc::kActionVmHasSnapshot) {
            result = handle_vm_has_snapshot(req.payload);
        } else if (req.action == ipc::kActionVmPrepareSnapshot) {
            result = handle_vm_prepare_snapshot(req.payload);
        } else if (req.action == ipc::kActionVmGetCaCert) {
            result = handle_vm_get_ca_cert(req.payload);
        } else if (req.action == ipc::kActionVmBuildAgent) {
            result = handle_vm_build_agent(req.payload);
        } else if (req.action == ipc::kActionVmGetAgentStatus) {
            result = handle_vm_get_agent_status(req.payload);
        // Log Analysis
        } else if (req.action == ipc::kActionGetLogResult) {
            result = handle_get_log_result(req.payload);
        } else if (req.action == ipc::kActionDeleteLogResult) {
            result = handle_delete_log_result(req.payload);
        } else if (req.action == ipc::kActionGetLogFormats) {
            result = handle_get_log_formats(req.payload);
        } else if (req.action == ipc::kActionOpenLogFile) {
            result = handle_open_log_file(req.payload);
        // Capture
        } else if (req.action == ipc::kActionGetCaptureStatus) {
            result = handle_get_capture_status(req.payload);
        } else if (req.action == ipc::kActionGetScreenshots) {
            result = handle_get_screenshots(req.payload);
        } else if (req.action == ipc::kActionGetDomSnapshots) {
            result = handle_get_dom_snapshots(req.payload);
        // Content Analysis
        } else if (req.action == ipc::kActionGetContentFindings) {
            result = handle_get_content_findings(req.payload);
        // Proxy
        } else if (req.action == ipc::kActionTestProxy) {
            result = handle_test_proxy(req.payload);
        // Report
        } else if (req.action == ipc::kActionPreviewReport) {
            result = handle_preview_report(req.payload);
        } else if (req.action == ipc::kActionSaveReport) {
            result = handle_save_report(req.payload);
        // Enrichment
        } else if (req.action == ipc::kActionEnrichmentQuery) {
            result = handle_enrichment_query(req.payload);
        } else if (req.action == ipc::kActionEnrichmentGetResults) {
            result = handle_enrichment_get_results(req.payload);
        // Sessions
        } else if (req.action == ipc::kActionSessionCreate) {
            result = handle_session_create(req.payload);
        } else if (req.action == ipc::kActionSessionDestroy) {
            result = handle_session_destroy(req.payload);
        } else if (req.action == ipc::kActionSessionList) {
            result = handle_session_list(req.payload);
        // Cloud Sandbox
        } else if (req.action == ipc::kActionCloudSandboxSubmit) {
            result = handle_cloud_sandbox_submit(req.payload);
        } else if (req.action == ipc::kActionCloudSandboxPoll) {
            result = handle_cloud_sandbox_poll(req.payload);
        } else {
            callback->Failure(404, ipc::make_error("unknown_action").dump());
            return true;
        }

        callback->Success(result.dump());
    } catch (const std::exception& e) {
        callback->Failure(500, ipc::make_error(e.what()).dump());
    } catch (...) {
        callback->Failure(500, ipc::make_error("internal_error").dump());
    }

    return true;
}

void MessageHandler::OnQueryCanceled(CefRefPtr<CefBrowser> /*browser*/,
                                     CefRefPtr<CefFrame> /*frame*/,
                                     int64_t /*query_id*/) {}

json MessageHandler::handle_navigate(CefRefPtr<CefBrowser> /*browser*/,
                                     const json& payload) {
    std::string url = payload.value("url", "");
    // If no URL, just create the content browser (view.create flow)
    if (url.empty()) {
        if (ui_client_) {
            ui_client_->navigate_content("about:blank");
        }
        return ipc::make_success();
    }
    if (url.compare(0, 7, "http://") != 0 &&
        url.compare(0, 8, "https://") != 0 &&
        url != "about:blank") {
        // Auto-prepend https:// for bare domains
        url = "https://" + url;
    }
    if (ui_client_) {
        ui_client_->navigate_content(url);
    }
    return ipc::make_success();
}

json MessageHandler::handle_get_tabs(const json& /*payload*/) {
    auto tabs = session_manager_->get_all_tabs();
    json tabs_json = json::array();
    for (const auto& tab : tabs) {
        tabs_json.push_back({
            {"tab_id", tab.tab_id},
            {"browser_id", tab.browser_id},
            {"in_memory", tab.in_memory}
        });
    }
    return ipc::make_success(tabs_json);
}

json MessageHandler::handle_close_tab(const json& payload) {
    int browser_id = payload.value("browser_id", -1);
    if (browser_id < 0) {
        return ipc::make_error("browser_id_required");
    }
    session_manager_->close_tab(browser_id);
    return ipc::make_success();
}

json MessageHandler::handle_analyze_download(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) {
        // Renderer may call this without sha256 (e.g., enrichment.query with IOC)
        return ipc::make_success({{"status", "no_file"}, {"results", json::array()}});
    }

    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        auto it = analysis_results_.find(sha256);
        if (it != analysis_results_.end()) {
            std::string status = it->second.value("status", "");
            if (status == "pending" || status == "complete") {
                return ipc::make_success({{"queued", false}, {"sha256", sha256},
                                          {"reason", "already_" + status}});
            }
        }
        // Clear previous result to allow reanalysis
        analysis_results_.erase(sha256);
    }

    // Delegate to auto_analyze which builds the full V1-compatible result shape
    auto_analyze(sha256);

    return ipc::make_success({{"queued", true}, {"sha256", sha256}});
}

json MessageHandler::handle_get_analysis_result(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    std::string file_id = payload.value("fileId", "");
    if (sha256.empty()) sha256 = file_id;

    if (sha256.empty()) {
        // No specific file — return all file analysis results (not emails)
        std::lock_guard<std::mutex> lock(results_mutex_);
        json arr = json::array();
        for (auto& [k, v] : analysis_results_) {
            // Skip email entries (keyed "email_*")
            if (k.compare(0, 6, "email_") == 0) continue;
            json entry = v;
            if (!entry.contains("sha256")) entry["sha256"] = k;
            if (!entry.contains("id")) entry["id"] = k;
            arr.push_back(entry);
        }
        return ipc::make_success(arr);
    }

    std::lock_guard<std::mutex> lock(results_mutex_);
    auto it = analysis_results_.find(sha256);
    if (it != analysis_results_.end()) {
        json result = it->second;
        result["sha256"] = sha256;
        if (!result.contains("id")) result["id"] = sha256;
        return ipc::make_success(result);
    }
    return ipc::make_success({{"status", "not_found"}});
}

json MessageHandler::handle_get_config(const json& payload) {
    std::string key = payload.value("key", "");
    if (key.empty()) {
        return ipc::make_success(config_store_->get_all());
    }
    return ipc::make_success(config_store_->get(key));
}

json MessageHandler::handle_set_config(const json& payload) {
    std::string key = payload.value("key", "");
    if (key.empty()) {
        return ipc::make_error("key_required");
    }
    if (!payload.contains("value")) {
        return ipc::make_error("value_required");
    }
    config_store_->set(key, payload["value"]);
    auto save_result = config_store_->save();
    if (!save_result.ok()) {
        return ipc::make_error(save_result.error().message);
    }
    return ipc::make_success();
}

json MessageHandler::handle_export_report(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    std::string format = payload.value("format", "json");
    std::string output_dir = payload.value("output_dir", ".");

    if (sha256.empty()) {
        return ipc::make_error("sha256_required");
    }

    json verdict_data;
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        auto it = analysis_results_.find(sha256);
        if (it == analysis_results_.end() || it->second.value("status", "") != "complete") {
            return ipc::make_error("analysis_not_complete");
        }
        verdict_data = it->second.value("verdict", json::object());
    }

    ThreatVerdict verdict = verdict_data.get<ThreatVerdict>();

    Result<std::string> result = (format == "html")
        ? export_manager_->export_html(verdict, sha256)
        : (format == "zip")
            ? export_manager_->export_zip(verdict, sha256, output_dir)
            : export_manager_->export_json(verdict, sha256);

    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }
    return ipc::make_success({{"path", result.value()}});
}

json MessageHandler::handle_get_threat_feeds(const json& /*payload*/) {
    return ipc::make_success({
        {"feeds", json::array()},
        {"indicator_count", threat_feed_manager_->indicator_count()}
    });
}

json MessageHandler::handle_start_capture(const json& payload) {
    int browser_id = payload.value("browser_id", -1);
    // V2: auto-resolve from content browser when shim sends sessionId
    if (browser_id < 0 && ui_client_ && ui_client_->content_browser()) {
        browser_id = ui_client_->content_browser()->GetIdentifier();
    }
    if (browser_id < 0) {
        return ipc::make_error("no_content_browser");
    }
    capture_manager_->start_capture(browser_id);
    return ipc::make_success();
}

json MessageHandler::handle_stop_capture(const json& payload) {
    int browser_id = payload.value("browser_id", -1);
    if (browser_id < 0 && ui_client_ && ui_client_->content_browser()) {
        browser_id = ui_client_->content_browser()->GetIdentifier();
    }
    if (browser_id < 0) {
        return ipc::make_error("no_content_browser");
    }
    capture_manager_->stop_capture(browser_id);

    auto requests = capture_manager_->get_requests(browser_id);
    auto har = har_builder_.build_string(requests);

    return ipc::make_success({
        {"request_count", requests.size()},
        {"har", har}
    });
}

json MessageHandler::handle_get_capture(const json& payload) {
    int browser_id = payload.value("browser_id", -1);
    if (browser_id < 0 && ui_client_ && ui_client_->content_browser()) {
        browser_id = ui_client_->content_browser()->GetIdentifier();
    }
    if (browser_id < 0) {
        // No content browser yet — return empty capture
        return ipc::make_success({
            {"capturing", false}, {"request_count", 0}, {"har", ""}
        });
    }

    auto requests = capture_manager_->get_requests(browser_id);
    auto har = har_builder_.build_string(requests);

    return ipc::make_success({
        {"capturing", capture_manager_->is_capturing(browser_id)},
        {"request_count", requests.size()},
        {"har", har}
    });
}

json MessageHandler::handle_nav_back(const json& /*payload*/) {
    if (ui_client_) ui_client_->content_go_back();
    return ipc::make_success();
}

json MessageHandler::handle_nav_forward(const json& /*payload*/) {
    if (ui_client_) ui_client_->content_go_forward();
    return ipc::make_success();
}

json MessageHandler::handle_nav_reload(const json& /*payload*/) {
    if (ui_client_) ui_client_->content_reload();
    return ipc::make_success();
}

json MessageHandler::handle_nav_stop(const json& /*payload*/) {
    if (ui_client_) ui_client_->content_stop();
    return ipc::make_success();
}

json MessageHandler::handle_set_content_bounds(const json& payload) {
    int x = payload.value("x", 0);
    int y = payload.value("y", 0);
    // React sends "width"/"height", accept both aliases
    int w = payload.contains("width") ? payload.value("width", 0) : payload.value("w", 0);
    int h = payload.contains("height") ? payload.value("height", 0) : payload.value("h", 0);
    if (w <= 0 || h <= 0) return ipc::make_success();
    if (ui_client_) {
        ui_client_->set_content_bounds(x, y, w, h);
    }
    return ipc::make_success();
}

json MessageHandler::handle_hide_content_browser(const json& /*payload*/) {
    if (ui_client_) {
        ui_client_->hide_content_browser();
    }
    return ipc::make_success();
}

json MessageHandler::handle_set_zoom(const json& payload) {
    double factor = payload.value("factor", 1.0);
    if (ui_client_) ui_client_->content_set_zoom(factor);
    return ipc::make_success();
}

json MessageHandler::handle_get_zoom(const json& /*payload*/) {
    double level = 0.0;
    if (ui_client_) level = ui_client_->content_get_zoom();
    return ipc::make_success({{"zoom", level}});
}

json MessageHandler::handle_start_vm(const json& payload) {
    std::string os = payload.value("os", "alpine");

    VmConfig config;
    if (os.find("indows") != std::string::npos) {
        config.platform = VmPlatform::kWindows;
    } else {
        config.platform = VmPlatform::kLinux;
    }
    config.enable_network = payload.value("enable_network", true);

    // Prefer Windows Sandbox when available (faster, no QEMU dependency).
    if (WindowsSandbox::is_available()) {
        if (event_bridge_) {
            event_bridge_->push_vm_status("booting");
        }

        auto* wsb = windows_sandbox_.get();
        auto* bridge = event_bridge_;

        std::jthread launcher([this, config, wsb, bridge](std::stop_token) {
            auto result = wsb->launch(config);
            if (result.ok()) {
                auto sid = result.value();
                {
                    std::lock_guard<std::mutex> lock(threads_mutex_);
                    active_wsb_session_ = sid;
                }
                if (bridge) bridge->push_vm_status("running");

#ifdef _WIN32
                // Connect RDP client to sandbox.
                std::this_thread::sleep_for(std::chrono::seconds(5));
                HWND st_hwnd = FindWindowA(nullptr, "ShieldTier");
                if (st_hwnd) {
                    RECT rc = {};
                    GetClientRect(st_hwnd, &rc);
                    int sidebar_w = 200;
                    int toolbar_h = 90;
                    auto rdp_result = wsb->connect_rdp(
                        sid, st_hwnd,
                        sidebar_w, toolbar_h,
                        rc.right - sidebar_w,
                        rc.bottom - toolbar_h);
                    if (rdp_result.ok()) {
                        if (bridge) bridge->push("wsb_embedded", {{"session_id", sid}});
                    } else {
                        fprintf(stderr, "[ShieldTier] RDP embed failed: %s\n",
                                rdp_result.error().message.c_str());
                    }
                }
#endif
            } else {
                if (bridge) bridge->push_vm_status("error");
            }
        });

        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            analysis_threads_.push_back(std::move(launcher));
        }

        return ipc::make_success({{"vm_id", "wsb_pending"}, {"provider", "windows_sandbox"}});
    }

    // Fallback to QEMU.
    auto result = vm_manager_->create_vm(config);
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }

    std::string vm_id = result.value();

    auto start_result = vm_manager_->start_vm(vm_id);
    if (!start_result.ok()) {
        return ipc::make_error(start_result.error().message);
    }

    if (event_bridge_) {
        event_bridge_->push_vm_status("booting");
    }

    auto* vm_mgr = vm_manager_.get();
    auto* bridge = event_bridge_;

    std::jthread monitor([vm_id, vm_mgr, bridge](std::stop_token stop) {
        while (!stop.stop_requested()) {
            VmState state = vm_mgr->get_state(vm_id);
            if (state == VmState::kReady || state == VmState::kAnalyzing) {
                if (bridge) bridge->push_vm_status("running");
                break;
            }
            if (state == VmState::kError) {
                if (bridge) bridge->push_vm_status("error");
                break;
            }
            if (state == VmState::kStopped) {
                if (bridge) bridge->push_vm_status("idle");
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        analysis_threads_.push_back(std::move(monitor));
    }

    return ipc::make_success({{"vm_id", vm_id}, {"provider", "qemu"}});
}

json MessageHandler::handle_stop_vm(const json& payload) {
    std::string vm_id = payload.value("vm_id", "");
    if (vm_id.empty()) vm_id = payload.value("instanceId", "");

    // Try stopping a Windows Sandbox session first.
    std::string wsb_session;
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        wsb_session = active_wsb_session_;
    }

    if (!wsb_session.empty() && (vm_id.empty() || vm_id == wsb_session)) {
        auto result = windows_sandbox_->stop(wsb_session);
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            active_wsb_session_.clear();
        }
        if (event_bridge_) {
            event_bridge_->push_vm_status("idle");
        }
        if (!result.ok()) {
            return ipc::make_error(result.error().message);
        }
        return ipc::make_success();
    }

    // Fallback: QEMU path.
    if (vm_id.empty()) {
        auto vms = vm_manager_->list_vms();
        if (!vms.empty()) {
            vm_id = vms.front().id;
        }
    }

    if (vm_id.empty()) {
        return ipc::make_error("no_active_vm");
    }

    auto result = vm_manager_->stop_vm(vm_id);
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }

    if (event_bridge_) {
        event_bridge_->push_vm_status("idle");
    }

    return ipc::make_success();
}

json MessageHandler::handle_wsb_focus_window(const json& /*payload*/) {
#ifdef _WIN32
    HWND sbx = FindWindowA(nullptr, "Windows Sandbox");
    if (sbx) {
        if (IsIconic(sbx)) ShowWindow(sbx, SW_RESTORE);
        SetForegroundWindow(sbx);
        return ipc::make_success({{"focused", true}});
    }
    return ipc::make_error("sandbox_window_not_found");
#else
    return ipc::make_error("windows_only");
#endif
}

// Helper: build VM analysis result from collected events (extracted to
// reduce nesting depth and avoid MSVC C1061 compiler limit).
static json build_wsb_result(const std::string& session_id,
                              const json& events_arr,
                              int poll_elapsed) {
    auto safe_str = [](const json& j, const char* key) -> std::string {
        if (!j.contains(key)) return "";
        auto& v = j[key];
        if (v.is_null()) return "";
        if (v.is_string()) return v.get<std::string>();
        return v.dump();
    };
    auto safe_int = [](const json& j, const char* key) -> int {
        if (!j.contains(key)) return 0;
        auto& v = j[key];
        if (v.is_number()) return v.get<int>();
        return 0;
    };

    json findings = json::array();
    json processes = json::array();
    json file_ops = json::array();
    json registry_ops = json::array();
    int process_count = 0;

    for (const auto& ev : events_arr) {
        auto cat = safe_str(ev, "category");
        auto act = safe_str(ev, "action");
        if (cat == "process" && act == "create") {
            process_count++;
            processes.push_back({
                {"pid", safe_int(ev, "pid")},
                {"name", safe_str(ev, "name")},
                {"commandLine", safe_str(ev, "path")},
            });
        } else if (cat == "file") {
            file_ops.push_back({
                {"operation", act},
                {"path", safe_str(ev, "path")},
            });
        } else if (cat == "registry") {
            registry_ops.push_back({
                {"operation", act},
                {"key", safe_str(ev, "key")},
                {"detail", safe_str(ev, "detail")},
            });
        }
    }

    int score = 0;
    if (process_count > 5) score += 20;
    if (!file_ops.empty()) score += 15;
    if (!registry_ops.empty()) score += 25;
    for (const auto& f : file_ops) {
        auto p = f.value("path", "");
        if (p.find("Startup") != std::string::npos) {
            score += 20;
            findings.push_back({{"severity","high"},{"category","persistence"},
                {"description","File dropped in Startup folder: " + p}});
        }
        if (p.find("payload") != std::string::npos) {
            score += 10;
            findings.push_back({{"severity","medium"},{"category","file_drop"},
                {"description","Suspicious file created: " + p}});
        }
        if (p.find("svchost") != std::string::npos) {
            score += 15;
            findings.push_back({{"severity","high"},{"category","masquerading"},
                {"description","File masquerading as system process: " + p}});
        }
    }
    for (const auto& r : registry_ops) {
        auto k = r.value("key", "") + r.value("detail", "");
        if (k.find("Run") != std::string::npos) {
            score += 25;
            findings.push_back({{"severity","high"},{"category","persistence"},
                {"description","Registry Run key modified"}});
        }
        if (k.find("service") != std::string::npos || k.find("Service") != std::string::npos) {
            score += 15;
            findings.push_back({{"severity","medium"},{"category","persistence"},
                {"description","New service installed"}});
        }
    }
    if (score > 100) score = 100;

    std::string verdict = score >= 70 ? "malicious" : score >= 30 ? "suspicious" : "clean";

    json stored = {
        {"vm_id", session_id},
        {"provider", "windows_sandbox"},
        {"success", true},
        {"duration_ms", poll_elapsed * 1000.0},
        {"events", events_arr},
        {"event_count", events_arr.size()},
        {"verdict", verdict},
        {"score", score},
        {"riskLevel", verdict},
        {"executionDurationMs", poll_elapsed * 1000.0},
        {"processTree", processes},
        {"processCount", process_count},
        {"fileOperations", file_ops},
        {"registryOperations", registry_ops},
        {"findings", findings},
        {"networkConnections", json::array()},
        {"memoryAllocations", json::array()},
        {"screenshots", json::array()},
        {"mitreTechniques", json::array()},
        {"networkSummary", {
            {"totalConnections", 0},
            {"uniqueHosts", json::array()},
            {"uniqueURLs", json::array()},
            {"dnsQueries", json::array()},
            {"httpRequests", 0},
        }},
    };

    // Build SandboxResult for AnalysisReportPanel
    json sandbox_result = {
        {"provider", "windows_sandbox"},
        {"status", "complete"},
        {"verdict", verdict},
        {"score", score},
        {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()},
        {"details", {
            {"scoreBreakdown", json::object()},
            {"categories", json::object()},
            {"mitreTechniques", json::array()},
            {"behaviorSummary", json::array()},
            {"detonation", {
                {"operations", json::array()},
                {"topOperations", json::array()},
                {"networkAttemptsDetail", json::array()},
            }},
        }},
    };

    auto& ops = sandbox_result["details"]["detonation"]["operations"];
    auto& summaries = sandbox_result["details"]["behaviorSummary"];
    for (const auto& ev : events_arr) {
        auto cat = safe_str(ev, "category");
        auto act = safe_str(ev, "action");
        auto detail = safe_str(ev, "detail");
        auto path = safe_str(ev, "path");
        ops.push_back({{"type", cat + "_" + act}, {"path", path.empty() ? detail : path}, {"detail", detail}});
    }
    for (const auto& f : findings) {
        summaries.push_back(f.value("description", ""));
    }

    stored["_sandbox_result"] = sandbox_result;
    return stored;
}

json MessageHandler::handle_submit_sample_to_vm(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) {
        sha256 = payload.value("fileId", "");
    }
    if (sha256.empty()) {
        return ipc::make_error("sha256_required");
    }

    auto file_opt = session_manager_->get_captured_download(sha256);
    if (!file_opt.has_value()) {
        return ipc::make_error("download_not_found");
    }

    // Check if Windows Sandbox is available — run everything on a background thread.
    std::string wsb_session;
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        wsb_session = active_wsb_session_;
    }

    if (WindowsSandbox::is_available()) {
        if (event_bridge_) {
            event_bridge_->push_vm_status("booting");
        }

        auto file_copy = file_opt.value();
        auto* wsb = windows_sandbox_.get();
        auto* bridge = event_bridge_;
        auto* config = config_store_.get();
        auto* inetsim = inetsim_server_.get();
        int timeout = payload.value("timeout", 300);
        bool enable_net = payload.contains("config")
            ? payload["config"].value("enableNetwork", false) : false;
        bool enable_inetsim = payload.contains("config")
            ? payload["config"].value("enableINetSim", true) : true;

        // INet (Fake) mode: disable networking entirely at the Hyper-V level.
        // Windows Sandbox ignores guest-OS firewall rules, so the only reliable
        // way to block real internet is <Networking>Disable</Networking>.
        // Mapped folders (C:\Samples, C:\Results) still work via VMBus.
        // Internet (Real) mode: enable networking for live analysis.
        bool wsb_networking = !enable_inetsim;

        // INetSim not needed — INet (Fake) mode uses <Networking>Disable</Networking>
        // which blocks all TCP/IP at the Hyper-V level.

        // Stage sample BEFORE launching sandbox so the agent finds it at boot.
        std::string net_mode = enable_inetsim ? "inetsim" : "internet";
        auto prepare_result = wsb->prepare_session(file_copy, wsb_networking, net_mode);
        if (!prepare_result.ok()) {
            if (bridge) {
                bridge->push_vm_status("error");
                bridge->push("vm_result", {
                    {"success", false},
                    {"error", prepare_result.error().message},
                });
            }
            return ipc::make_error(prepare_result.error().message);
        }
        auto prepared_id = prepare_result.value();

        std::jthread worker([this, prepared_id, wsb, bridge, config, inetsim,
                             timeout, wsb_networking, enable_inetsim, sha256](std::stop_token stoken) {
            // Launch the sandbox with sample already staged.
            VmConfig wsb_config;
            wsb_config.platform = VmPlatform::kWindows;
            wsb_config.enable_network = wsb_networking;
            wsb_config.enable_inetsim = enable_inetsim;

            auto launch_result = wsb->launch(prepared_id, wsb_config);
            if (!launch_result.ok()) {
                if (bridge) {
                    bridge->push_vm_status("error");
                    bridge->push("vm_result", {
                        {"success", false},
                        {"error", launch_result.error().message},
                    });
                }
                return;
            }

            std::string session_id = launch_result.value();
            {
                std::lock_guard<std::mutex> lock(threads_mutex_);
                active_wsb_session_ = session_id;
            }

            // Sandbox is booting — the standalone Windows Sandbox window
            // is visible.  Tell the UI so it can show "Switch to VM Window".
            if (bridge) {
                bridge->push_vm_status("running");
                bridge->push("wsb_running", {
                    {"session_id", session_id},
                    {"provider", "windows_sandbox"},
                });
            }
            fprintf(stderr, "[ShieldTier] Sandbox launched, user can switch to VM window\n");

            // Get results dir NOW while session is alive.
            std::string results_dir = wsb->get_results_dir(session_id);
            for (auto& c : results_dir) { if (c == '/') c = '\\'; }
            auto events_path = results_dir + "\\events.jsonl";

            // Wait for WindowsSandboxServer.exe to start (takes 5-15 seconds)
            if (bridge) bridge->push_vm_status("booting");
            for (int wait = 0; wait < 30 && !stoken.stop_requested(); ++wait) {
                if (wsb->is_running(session_id)) break;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            fprintf(stderr, "[ShieldTier] Sandbox server running: %s\n",
                    wsb->is_running(session_id) ? "yes" : "no");

            // Poll every second. Continuously read events while sandbox runs.
            // We must read BEFORE sandbox stops because mapped folders
            // disappear when the VM shuts down.
            if (bridge) bridge->push_vm_status("executing");
            json events_arr = json::array();
            int poll_elapsed = 0;
            while (poll_elapsed < timeout &&
                   (wsb->is_running(session_id) || poll_elapsed < 30) &&
                   !stoken.stop_requested()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                poll_elapsed += 1;

                // Read events on every poll (file may grow as agent collects)
                json latest_events = json::array();
                {
                    std::ifstream evf(events_path);
                    if (evf.is_open()) {
                        std::string line;
                        while (std::getline(evf, line)) {
                            if (line.empty()) continue;
                            if (!line.empty() && line.back() == '\r') line.pop_back();
                            if (line.empty()) continue;
                            if (line.size() >= 3 &&
                                static_cast<unsigned char>(line[0]) == 0xEF &&
                                static_cast<unsigned char>(line[1]) == 0xBB &&
                                static_cast<unsigned char>(line[2]) == 0xBF) {
                                line = line.substr(3);
                            }
                            try { latest_events.push_back(json::parse(line)); } catch (...) {}
                        }
                    }
                }
                if (latest_events.size() > events_arr.size()) {
                    events_arr = std::move(latest_events);
                    // Push live event count to UI
                    if (bridge) {
                        bridge->push("vm_status", {
                            {"status", "executing"},
                            {"progress", std::to_string(events_arr.size()) + " events collected"},
                        });
                    }
                }
            }

            if (bridge) bridge->push_vm_status("collecting");
            fprintf(stderr, "[ShieldTier] Collected %d events from sandbox\n",
                    (int)events_arr.size());

            // Build results (extracted to static helper to reduce nesting)
            json stored = build_wsb_result(session_id, events_arr, poll_elapsed);
            auto verdict = stored.value("verdict", "clean");
            auto score = stored.value("score", 0);

            fprintf(stderr, "[ShieldTier] WSB analysis complete: %d events, score=%d, verdict=%s\n",
                    (int)events_arr.size(), score, verdict.c_str());

            // Store result BEFORE pushing to UI (so getResult finds it)
            if (config) {
                config->set("vm_result_" + session_id, stored);
                config->save();
            }

            // Push as file analysis update so AnalysisReportPanel picks it up.
            // The panel reads from staticAnalysis.metadata.detonation.operations
            // and staticAnalysis.findings.
            if (bridge && !sha256.empty()) {
                auto sandbox_result = stored["_sandbox_result"];

                // Build detonation operations in the format AnalysisReportPanel expects
                json det_operations = json::array();
                for (const auto& ev : events_arr) {
                    auto cat = stored.contains("_sandbox_result") ?
                        (ev.contains("category") && ev["category"].is_string() ? ev["category"].get<std::string>() : "") : "";
                    auto act = ev.contains("action") && ev["action"].is_string() ? ev["action"].get<std::string>() : "";
                    auto path = ev.contains("path") && ev["path"].is_string() ? ev["path"].get<std::string>() : "";
                    auto detail = ev.contains("detail") && ev["detail"].is_string() ? ev["detail"].get<std::string>() : "";
                    auto name = ev.contains("name") && ev["name"].is_string() ? ev["name"].get<std::string>() : "";

                    std::string op_type;
                    if (cat == "process") op_type = "process_create";
                    else if (cat == "file") op_type = "file_" + act;
                    else if (cat == "registry") op_type = "registry_" + act;
                    else if (cat == "network") op_type = "network_" + act;
                    else op_type = cat + "_" + act;

                    det_operations.push_back({
                        {"type", op_type},
                        {"target", path.empty() ? detail : path},
                        {"data", detail.empty() ? name : detail},
                    });
                }

                json file_update = {
                    {"sha256", sha256},
                    {"id", sha256},
                    {"sandboxResults", json::array({sandbox_result})},
                    {"behavioralAnalysisDone", true},
                    {"behavioralAnalysisRunning", false},
                    {"staticAnalysis", {
                        {"findings", stored["findings"]},
                        {"metadata", {
                            {"detonation", {
                                {"operations", det_operations},
                                {"operationCount", det_operations.size()},
                                {"topOperations", json::array()},
                                {"networkAttemptsDetail", json::array()},
                                {"networkTraffic", json::array()},
                            }},
                        }},
                    }},
                };
                bridge->push_analysis_complete(sha256, file_update);
            }

            if (bridge) {
                bridge->push_vm_status("completed");
                bridge->push("vm_result", stored);
            }
        });

        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            analysis_threads_.push_back(std::move(worker));
        }

        return ipc::make_success({{"vm_id", prepared_id}, {"provider", "windows_sandbox"}});
    }

    // Fallback: QEMU path.
    auto vms = vm_manager_->list_vms();
    if (vms.empty()) {
        return ipc::make_error("no_active_vm");
    }

    std::string vm_id = vms.front().id;

    if (event_bridge_) {
        event_bridge_->push_vm_status("running");
    }

    auto file_copy = file_opt.value();
    auto* vm_mgr = vm_manager_.get();
    auto* bridge = event_bridge_;
    auto* config = config_store_.get();

    std::jthread worker([vm_id, file_copy, vm_mgr, bridge, config](std::stop_token) {
        auto result = vm_mgr->submit_sample(vm_id, file_copy);

        if (result.ok()) {
            auto& vm_result = result.value();

            VmScoring scorer;
            json network_activity;
            auto scored = scorer.score_vm_results(
                vm_result.events, network_activity, vm_result.duration_ms);

            json stored = {
                {"vm_id", vm_id},
                {"provider", "qemu"},
                {"success", vm_result.success},
                {"duration_ms", vm_result.duration_ms},
                {"event_count", vm_result.events.size()},
                {"events", vm_result.events},
            };
            if (scored.ok()) {
                auto& scored_result = scored.value();
                stored["findings"] = scored_result.findings;
                stored["threat_score"] = scored_result.raw_output.value("finding_count", 0);
                stored["raw_output"] = scored_result.raw_output;
            }

            std::string result_key = "vm_result_" + vm_id;
            config->set(result_key, stored);
            config->save();

            if (bridge) {
                bridge->push_vm_status("complete");
                bridge->push("vm_result", stored);
            }
        } else {
            if (bridge) {
                bridge->push_vm_status("error");
                bridge->push("vm_result", {
                    {"vm_id", vm_id},
                    {"provider", "qemu"},
                    {"success", false},
                    {"error", result.error().message},
                });
            }
        }
    });

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        analysis_threads_.push_back(std::move(worker));
    }

    return ipc::make_success({{"vm_id", vm_id}, {"provider", "qemu"}});
}

json MessageHandler::handle_analyze_email(const json& payload) {
    std::string raw_source = payload.value("rawSource", "");
    const uint8_t* data = nullptr;
    size_t data_size = 0;
    FileBuffer fb;

    if (!raw_source.empty()) {
        data = reinterpret_cast<const uint8_t*>(raw_source.data());
        data_size = raw_source.size();
        fb.data.assign(raw_source.begin(), raw_source.end());
        fb.filename = "email.eml";
        fb.mime_type = "message/rfc822";
    } else {
        std::string sha256 = payload.value("sha256", "");
        if (sha256.empty()) return ipc::make_error("rawSource or sha256 required");
        auto file_opt = session_manager_->get_captured_download(sha256);
        if (!file_opt.has_value()) return ipc::make_error("download_not_found");
        fb = file_opt.value();
        data = fb.ptr();
        data_size = fb.size();
    }

    // Step 1: Parse the email (MIME structure)
    auto parsed = email_analyzer_->parse(data, data_size);
    if (!parsed.ok()) return ipc::make_error(parsed.error().message);
    auto& email = parsed.value();

    // Step 2: Run analysis (findings, phishing indicators)
    auto analysis = email_analyzer_->analyze(fb);

    // Step 3: Build V1-compatible response (exact field names from V1 ParsedEmail)
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string email_id = "email_" + std::to_string(now_ms);
    std::string session_id = payload.value("sessionId", "");

    // Headers as {name: value} object
    json headers_obj = json::object();
    for (const auto& h : email.headers) {
        std::string key = h.name;
        for (auto& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (headers_obj.contains(key)) {
            headers_obj[key] = headers_obj[key].get<std::string>() + "\n" + h.value;
        } else {
            headers_obj[key] = h.value;
        }
    }

    // URLs as ExtractedURL objects
    json urls_json = json::array();
    for (const auto& u : email.urls_in_body) {
        urls_json.push_back({
            {"url", u}, {"displayText", u}, {"mismatch", false}, {"source", "text"}
        });
    }

    // Attachments as EmailAttachment objects
    // Store attachment data in SessionManager for file analysis pipeline
    json attachments_json = json::array();
    for (size_t i = 0; i < email.attachments.size(); ++i) {
        const auto& att = email.attachments[i];
        bool has_data = !att.data.empty() && !att.sha256.empty();

        if (has_data) {
            // Store the attachment binary in captured_files so the file
            // analysis pipeline can pick it up (same as download interception)
            std::vector<uint8_t> att_data(att.data.begin(), att.data.end());
            session_manager_->store_captured_file(
                att.sha256, std::move(att_data),
                att.filename, att.content_type);
        }

        attachments_json.push_back({
            {"id", "att_" + std::to_string(i)},
            {"filename", att.filename},
            {"contentType", att.content_type},
            {"size", att.data.size()},
            {"extracted", has_data},
            {"sha256", att.sha256},
            {"quarantineFileId", has_data ? att.sha256 : ""},
        });
    }

    // Findings from analysis
    json findings_json = json::array();
    json phishing_indicators = json::array();
    if (analysis.ok()) {
        for (const auto& f : analysis.value().findings) {
            findings_json.push_back({
                {"title", f.title}, {"description", f.description},
                {"severity", f.severity}, {"engine", f.engine}, {"metadata", f.metadata}
            });
            // Convert findings to phishing indicators
            std::string cat = "content";
            if (f.title.find("SPF") != std::string::npos ||
                f.title.find("DKIM") != std::string::npos ||
                f.title.find("DMARC") != std::string::npos)
                cat = "authentication";
            else if (f.title.find("spoof") != std::string::npos ||
                     f.title.find("mismatch") != std::string::npos)
                cat = "spoofing";
            else if (f.title.find("URL") != std::string::npos ||
                     f.title.find("link") != std::string::npos)
                cat = "links";
            else if (f.title.find("attach") != std::string::npos)
                cat = "attachments";

            std::string mitre = f.metadata.value("mitre_technique", "");
            json indicator = {
                {"id", "ind_" + std::to_string(phishing_indicators.size())},
                {"category", cat},
                {"severity", f.severity},
                {"description", f.title},
                {"evidence", f.description},
            };
            if (!mitre.empty()) indicator["mitre"] = mitre;
            phishing_indicators.push_back(indicator);
        }
    }

    // ── Phishing score — V1-matching weighted heuristic analysis ──
    // The engine findings contribute, but we also run content heuristics
    // to catch common phishing patterns the engine may miss.

    int score_spoofing = 0;
    int score_auth = 0;
    int score_content = 0;
    int score_links = 0;
    int score_attachments = 0;
    int score_urgency = 0;
    int score_brand = 0;

    // (1) Engine findings contribute to score
    for (const auto& f : findings_json) {
        std::string sev = f.value("severity", "info");
        int pts = (sev == "critical") ? 15 : (sev == "high") ? 8 :
                  (sev == "medium") ? 4 : (sev == "low") ? 1 : 0;
        score_content += pts;
    }

    // (2) Sender domain mismatch: display name suggests institution but uses freemail
    auto from_str = email.from;
    std::string from_lower = from_str;
    for (auto& c : from_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Extract email address from "Display Name <email@domain>"
    std::string sender_email;
    auto angle_open = from_lower.find('<');
    auto angle_close = from_lower.find('>');
    if (angle_open != std::string::npos && angle_close != std::string::npos) {
        sender_email = from_lower.substr(angle_open + 1, angle_close - angle_open - 1);
    } else {
        sender_email = from_lower;
    }
    std::string sender_domain;
    auto at_pos = sender_email.find('@');
    if (at_pos != std::string::npos) {
        sender_domain = sender_email.substr(at_pos + 1);
    }

    // Freemail providers used for impersonation
    static const std::vector<std::string> freemail_domains = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
        "protonmail.com", "mail.com", "yandex.com", "zoho.com", "gmx.com",
        "icloud.com", "live.com", "msn.com", "qq.com", "163.com",
        "mail.ru", "rambler.ru", "inbox.com", "tutanota.com",
    };
    bool is_freemail = false;
    for (const auto& fm : freemail_domains) {
        if (sender_domain == fm) { is_freemail = true; break; }
    }

    // Display name contains institutional/brand keywords but uses freemail
    std::string display_name = (angle_open != std::string::npos)
        ? from_lower.substr(0, angle_open) : "";
    // Trim
    while (!display_name.empty() && (display_name.back() == ' ' || display_name.back() == '"'))
        display_name.pop_back();
    while (!display_name.empty() && (display_name.front() == ' ' || display_name.front() == '"'))
        display_name.erase(display_name.begin());

    static const std::vector<std::string> brand_keywords = {
        "bank", "banco", "paypal", "amazon", "apple", "microsoft", "google",
        "netflix", "facebook", "instagram", "whatsapp", "chase", "wells fargo",
        "citibank", "hsbc", "barclays", "santander", "itau", "bradesco", "bb ",
        "caixa", "nubank", "inter", "security", "secure", "support", "help",
        "service", "billing", "account", "verify", "update", "confirm",
        "notification", "notificacao", "alert", "warning", "suspended",
        "locked", "expired", "resgate", "credito", "pagamento", "fatura",
        "dhl", "fedex", "ups", "usps", "irs", "hmrc", "gov",
    };
    bool display_has_brand = false;
    for (const auto& kw : brand_keywords) {
        if (display_name.find(kw) != std::string::npos) {
            display_has_brand = true;
            break;
        }
    }

    if (is_freemail && display_has_brand) {
        score_spoofing += 25;
        phishing_indicators.push_back({
            {"id", "ind_spoof_freemail"},
            {"category", "spoofing"},
            {"severity", "high"},
            {"description", "Sender uses freemail (" + sender_domain + ") but display name impersonates a brand/institution"},
            {"evidence", email.from},
        });
    } else if (is_freemail && !display_name.empty() && display_name.size() > 5) {
        // Freemail with a long display name is mildly suspicious
        score_spoofing += 5;
    }

    // Return-path vs From mismatch
    if (!email.return_path.empty()) {
        std::string rp_lower = email.return_path;
        for (auto& c : rp_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (rp_lower.find(sender_domain) == std::string::npos && !sender_domain.empty()) {
            score_spoofing += 10;
            phishing_indicators.push_back({
                {"id", "ind_spoof_returnpath"},
                {"category", "spoofing"},
                {"severity", "medium"},
                {"description", "Return-Path domain doesn't match sender domain"},
                {"evidence", "From: " + sender_domain + ", Return-Path: " + email.return_path},
            });
        }
    }

    // (3) Urgency / financial lure keywords in subject + body
    std::string text_for_analysis = email.subject + " " + email.body_text;
    if (text_for_analysis.size() < 50 && !email.body_html.empty()) {
        text_for_analysis += " " + email.body_html;
    }
    std::string text_lower = text_for_analysis;
    for (auto& c : text_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    static const std::vector<std::string> urgency_keywords = {
        "urgent", "urgente", "immediately", "imediatamente", "expire",
        "suspend", "block", "locked", "verify your", "verifique",
        "confirm your", "confirme", "within 24", "within 48",
        "action required", "act now", "immediate action",
        "your account", "sua conta", "will be closed",
        "will be suspended", "unauthorized", "unusual activity",
        "click here", "clique aqui",
    };
    for (const auto& kw : urgency_keywords) {
        if (text_lower.find(kw) != std::string::npos) {
            score_urgency += 5;
            break;  // Count once
        }
    }

    static const std::vector<std::string> financial_keywords = {
        "payment", "pagamento", "transfer", "transferencia",
        "withdraw", "saque", "pendentes", "pending",
        "invoice", "fatura", "refund", "reembolso",
        "credit", "credito", "debit", "debito",
        "r$", "$", "€", "£", "amount due", "balance",
        "saldo", "resgate", "prize", "premio",
        "lottery", "loteria", "won", "ganhou",
        "inheritance", "herança", "million", "milhao",
    };
    int financial_hits = 0;
    for (const auto& kw : financial_keywords) {
        if (text_lower.find(kw) != std::string::npos) {
            financial_hits++;
        }
    }
    if (financial_hits >= 3) {
        score_content += 15;
        phishing_indicators.push_back({
            {"id", "ind_financial_lure"},
            {"category", "content"},
            {"severity", "high"},
            {"description", "Email contains multiple financial/monetary keywords typical of phishing lures"},
            {"evidence", std::to_string(financial_hits) + " financial keywords detected"},
        });
    } else if (financial_hits >= 1) {
        score_content += 5;
    }

    // (4) Generic greeting
    static const std::vector<std::string> generic_greetings = {
        "dear customer", "dear client", "dear user", "dear sir",
        "dear madam", "dear account holder", "valued customer",
        "prezado cliente", "caro cliente", "estimado cliente",
        "dear member", "dear valued",
    };
    for (const auto& g : generic_greetings) {
        if (text_lower.find(g) != std::string::npos) {
            score_content += 5;
            phishing_indicators.push_back({
                {"id", "ind_generic_greeting"},
                {"category", "content"},
                {"severity", "low"},
                {"description", "Uses generic greeting instead of recipient's name"},
                {"evidence", g},
            });
            break;
        }
    }

    // (5) Attachment-based lure: "open/follow attachment" language + has attachments
    if (!email.attachments.empty()) {
        score_attachments += 5;  // Having attachments is baseline suspicious
        static const std::vector<std::string> attachment_lure = {
            "open the attach", "abra o anexo", "arquivo anexo",
            "see attached", "veja o anexo", "attached file",
            "download the attach", "instrucoes do arquivo",
            "instruções do arquivo", "open attached",
        };
        for (const auto& kw : attachment_lure) {
            if (text_lower.find(kw) != std::string::npos) {
                score_attachments += 15;
                phishing_indicators.push_back({
                    {"id", "ind_attachment_lure"},
                    {"category", "attachments"},
                    {"severity", "high"},
                    {"description", "Email directs recipient to open attachment — common phishing/malware delivery tactic"},
                    {"evidence", kw},
                });
                break;
            }
        }

        // Dangerous attachment types
        for (const auto& att : email.attachments) {
            std::string fn_lower = att.filename;
            for (auto& c : fn_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            static const std::vector<std::string> dangerous_exts = {
                ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                ".hta", ".msi", ".dll", ".com", ".pif", ".wsf",
                ".jar", ".iso", ".img", ".lnk",
            };
            for (const auto& ext : dangerous_exts) {
                if (fn_lower.size() >= ext.size() &&
                    fn_lower.compare(fn_lower.size() - ext.size(), ext.size(), ext) == 0) {
                    score_attachments += 20;
                    phishing_indicators.push_back({
                        {"id", "ind_dangerous_attachment"},
                        {"category", "attachments"},
                        {"severity", "critical"},
                        {"description", "Dangerous executable attachment type: " + ext},
                        {"evidence", att.filename},
                    });
                    break;
                }
            }
        }
    }

    // (6) Suspicious links: mismatched display text vs href, shortened URLs
    for (const auto& u : email.urls_in_body) {
        std::string u_lower = u;
        for (auto& c : u_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        static const std::vector<std::string> shorteners = {
            "bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "short.link",
        };
        for (const auto& s : shorteners) {
            if (u_lower.find(s) != std::string::npos) {
                score_links += 10;
                phishing_indicators.push_back({
                    {"id", "ind_url_shortener"},
                    {"category", "links"},
                    {"severity", "medium"},
                    {"description", "Email contains shortened URL which may hide malicious destination"},
                    {"evidence", u},
                });
                break;
            }
        }
    }

    // (7) Authentication failures
    for (const auto& a : email.authentication) {
        std::string result_lower = a.result;
        for (auto& c : result_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (result_lower == "fail" || result_lower == "softfail") {
            std::string method_upper = a.method;
            for (auto& c : method_upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            score_auth += (result_lower == "fail") ? 15 : 8;
            phishing_indicators.push_back({
                {"id", "ind_auth_" + a.method},
                {"category", "authentication"},
                {"severity", result_lower == "fail" ? "high" : "medium"},
                {"description", method_upper + " " + a.result + " for " + a.domain},
                {"evidence", a.method + "=" + a.result},
            });
        }
    }

    // Aggregate score
    int score = score_spoofing + score_auth + score_content +
                score_links + score_attachments + score_urgency + score_brand;
    if (score > 100) score = 100;
    std::string verdict = score >= 65 ? "likely_phishing" :
                          score >= 35 ? "suspicious" : "likely_legitimate";

    // Always emit phishingScore so renderer transitions from "analyzing" → "complete"
    json phishing_score = {
        {"score", score},
        {"verdict", verdict},
        {"indicators", phishing_indicators},
        {"breakdown", {
            {"spoofing", score_spoofing},
            {"authentication", score_auth},
            {"content", score_content},
            {"links", score_links},
            {"attachments", score_attachments},
            {"urgency", score_urgency},
            {"brand", score_brand}
        }}
    };

    // Build the full V1-compatible ParsedEmail response
    json response = {
        {"id", email_id},
        {"sessionId", session_id},
        {"parsedAt", now_ms},
        {"from", email.from},
        {"to", email.to},
        {"cc", email.cc},
        {"subject", email.subject},
        {"returnPath", email.return_path},
        {"date", email.date},
        {"headers", headers_obj},
        {"textBody", email.body_text},
        {"htmlBody", email.body_html},
        {"receivedChain", [&]() {
            json chain = json::array();
            for (const auto& hop : email.received_chain) {
                chain.push_back({
                    {"from", hop.from}, {"by", hop.by},
                    {"timestamp", hop.timestamp}, {"delay", hop.delay},
                    {"ip", hop.ip}
                });
            }
            return chain;
        }()},
        {"authentication", [&]() {
            json auth = json::array();
            for (const auto& a : email.authentication) {
                auth.push_back({
                    {"method", a.method}, {"result", a.result}, {"domain", a.domain}
                });
            }
            return auth;
        }()},
        {"urls", urls_json},
        {"attachments", attachments_json},
        {"phishingScore", phishing_score},
        {"findings", findings_json},
        {"rawSource", raw_source.empty() ? std::string(reinterpret_cast<const char*>(data), std::min(data_size, size_t(512 * 1024))) : raw_source},
    };

    // Store for getEmails/getEmail retrieval
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        analysis_results_[email_id] = response;
    }

    // Emit to renderer
    if (event_bridge_) {
        event_bridge_->push("email_parsed", {
            {"sessionId", session_id},
            {"email", response}
        });
    }

    // Phase 5b: Register email URLs as IOCs (match V1's enrichmentManager.registerIOC)
    // Push IOC entries to the renderer via enrichment_result events
    if (event_bridge_ && !email.urls_in_body.empty()) {
        for (const auto& url_str : email.urls_in_body) {
            json ioc_event = {
                {"sessionId", session_id},
                {"value", url_str},
                {"type", "url"},
                {"source", "email"},
                {"firstSeen", now_ms},
                {"results", json::array()},
                {"status", "pending"},
                {"safe", false},
                {"domain", ""}
            };
            // Extract domain from URL
            auto scheme_end = url_str.find("://");
            if (scheme_end != std::string::npos) {
                auto host_start = scheme_end + 3;
                auto host_end = url_str.find_first_of(":/?#", host_start);
                std::string host = (host_end == std::string::npos)
                    ? url_str.substr(host_start)
                    : url_str.substr(host_start, host_end - host_start);
                ioc_event["domain"] = host;
                // Also register the domain itself
                json domain_event = {
                    {"sessionId", session_id},
                    {"value", host}, {"type", "domain"}, {"source", "email"},
                    {"firstSeen", now_ms}, {"results", json::array()},
                    {"status", "pending"}, {"safe", false}, {"domain", host}
                };
                event_bridge_->push("enrichment_result", domain_event);
            }
            event_bridge_->push("enrichment_result", ioc_event);
        }
    }

    // Phase 5c: YARA scan on email body (match V1's yaraManager.scanContent)
    {
        std::string email_content = email.body_text;
        if (email_content.empty()) email_content = email.body_html;
        if (!email_content.empty()) {
            FileBuffer email_fb;
            email_fb.data.assign(email_content.begin(), email_content.end());
            email_fb.filename = "email_body.txt";
            email_fb.mime_type = "text/plain";
            auto yara_result = yara_engine_->scan(email_fb);
            if (yara_result.ok() && !yara_result.value().findings.empty()) {
                json yara_matches = json::array();
                for (const auto& f : yara_result.value().findings) {
                    yara_matches.push_back({
                        {"ruleName", f.title}, {"description", f.description},
                        {"severity", f.severity}, {"metadata", f.metadata}
                    });
                }
                // Add YARA matches to the response
                response["yaraMatches"] = yara_matches;
                // Also add to findings
                for (const auto& f : yara_result.value().findings) {
                    findings_json.push_back({
                        {"title", "YARA: " + f.title}, {"description", f.description},
                        {"severity", f.severity}, {"engine", "yara"}, {"metadata", f.metadata}
                    });
                }
                response["findings"] = findings_json;
                // Emit yara_scan_result event
                if (event_bridge_) {
                    event_bridge_->push("yara_scan_result", {
                        {"sessionId", session_id},
                        {"source", "email_body"},
                        {"matches", yara_matches}
                    });
                }
            }
        }
    }

    // Extract URIs from PDF attachments and register as IOCs immediately
    // (auto_analyze runs on a background thread, so we also do it here for instant visibility)
    if (event_bridge_) {
        for (const auto& att : email.attachments) {
            if (att.data.empty()) continue;
            // Check if it's a PDF by magic bytes
            bool is_pdf = att.data.size() >= 5 &&
                att.data[0] == '%' && att.data[1] == 'P' &&
                att.data[2] == 'D' && att.data[3] == 'F';
            if (!is_pdf && att.content_type.find("pdf") == std::string::npos) continue;

            // Extract /URI entries from PDF content
            std::string pdf_str(att.data.begin(), att.data.end());
            fprintf(stderr, "[ShieldTier] PDF attachment '%s': size=%zu is_pdf=%d\n",
                    att.filename.c_str(), att.data.size(), (int)is_pdf);
            std::regex uri_re("/URI\\s*\\(([^)]+)\\)");
            std::sregex_iterator it(pdf_str.begin(), pdf_str.end(), uri_re);
            std::sregex_iterator end_it;
            int uri_count = 0;
            for (; it != end_it; ++it) {
                std::string uri = (*it)[1].str();
                uri_count++;
                fprintf(stderr, "[ShieldTier] PDF URI found: %s\n", uri.c_str());
                if (!uri.empty()) {
                    // Extract domain
                    std::string domain;
                    auto se = uri.find("://");
                    if (se != std::string::npos) {
                        auto hs = se + 3;
                        auto he = uri.find_first_of(":/?#", hs);
                        domain = (he == std::string::npos) ? uri.substr(hs) : uri.substr(hs, he - hs);
                    }
                    event_bridge_->push("enrichment_result", {
                        {"sessionId", session_id},
                        {"value", uri}, {"type", "url"},
                        {"source", "pdf_attachment"}, {"status", "pending"},
                        {"safe", false}, {"domain", domain},
                        {"firstSeen", now_ms}, {"results", json::array()},
                    });
                    // Also register the domain
                    if (!domain.empty()) {
                        event_bridge_->push("enrichment_result", {
                            {"sessionId", session_id},
                            {"value", domain}, {"type", "domain"},
                            {"source", "pdf_attachment"}, {"status", "pending"},
                            {"safe", false}, {"domain", domain},
                            {"firstSeen", now_ms}, {"results", json::array()},
                        });
                    }
                }
            }

            // Also extract URLs from /SubmitForm actions: /F << ... /F (url) >>
            {
                std::regex submit_re("/SubmitForm[^>]*?/F\\s*\\(([^)]+)\\)");
                std::sregex_iterator sit(pdf_str.begin(), pdf_str.end(), submit_re);
                std::sregex_iterator sit_end;
                for (; sit != sit_end; ++sit) {
                    std::string submit_url = (*sit)[1].str();
                    if (!submit_url.empty() && submit_url.find("://") != std::string::npos) {
                        std::string sdomain;
                        auto sse = submit_url.find("://");
                        if (sse != std::string::npos) {
                            auto shs = sse + 3;
                            auto she = submit_url.find_first_of(":/?#", shs);
                            sdomain = (she == std::string::npos) ? submit_url.substr(shs) : submit_url.substr(shs, she - shs);
                        }
                        event_bridge_->push("enrichment_result", {
                            {"sessionId", session_id},
                            {"value", submit_url}, {"type", "url"},
                            {"source", "pdf_submitform"}, {"status", "pending"},
                            {"safe", false}, {"domain", sdomain},
                            {"firstSeen", now_ms}, {"results", json::array()},
                        });
                    }
                }
            }
        }
    }

    // Auto-analyze extracted attachments through the file analysis pipeline
    for (const auto& att : email.attachments) {
        if (!att.data.empty() && !att.sha256.empty()) {
            auto_analyze(att.sha256);
        }
    }

    return ipc::make_success(response);
}

json MessageHandler::handle_analyze_logs(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) {
        std::string file_path = payload.value("filePath", "");
        if (file_path.empty()) {
            return ipc::make_success({{"status", "no_file"}});
        }
    }

    auto file_opt = session_manager_->get_captured_download(sha256);
    if (!file_opt.has_value()) {
        return ipc::make_error("download_not_found");
    }

    auto result = log_manager_->analyze(file_opt.value());
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }

    auto& r = result.value();
    json findings_json = json::array();
    for (const auto& f : r.findings) {
        findings_json.push_back({
            {"title", f.title}, {"description", f.description},
            {"severity", f.severity}, {"engine", f.engine}, {"metadata", f.metadata}
        });
    }

    return ipc::make_success({
        {"engine", "loganalysis"},
        {"findings", findings_json},
        {"duration_ms", r.duration_ms},
        {"raw_output", r.raw_output}
    });
}

json MessageHandler::handle_get_log_results(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) {
        // Return all log analysis results (keyed "log_*")
        std::lock_guard<std::mutex> lock(results_mutex_);
        json arr = json::array();
        for (const auto& [k, v] : analysis_results_) {
            if (k.compare(0, 4, "log_") == 0) {
                arr.push_back(v);
            }
        }
        return ipc::make_success(arr);
    }

    auto file_opt = session_manager_->get_captured_download(sha256);
    if (!file_opt.has_value()) {
        return ipc::make_error("download_not_found");
    }

    const auto& file = file_opt.value();
    auto format = log_manager_->detect_format(file.ptr(), file.size());
    auto events = log_manager_->parse(file.ptr(), file.size(), format);
    if (!events.ok()) {
        return ipc::make_error(events.error().message);
    }

    json events_json = json::array();
    for (const auto& evt : events.value()) {
        events_json.push_back({
            {"timestamp", evt.timestamp}, {"source", evt.source},
            {"event_type", evt.event_type}, {"severity", evt.severity},
            {"message", evt.message}, {"fields", evt.fields}
        });
    }

    return ipc::make_success({{"events", events_json}, {"count", events_json.size()}});
}

json MessageHandler::handle_chat_get_identity(const json& /*payload*/) {
    auto pubkey = chat_manager_->get_public_key();
    auto pubkey_b64 = ShieldCrypt::encode_base64(pubkey);
    return ipc::make_success({
        {"session_id", pubkey_b64.substr(0, 16)},
        {"public_key", pubkey_b64}
    });
}

json MessageHandler::handle_chat_get_contacts(const json& /*payload*/) {
    auto contacts = chat_manager_->get_contacts();
    json contacts_json = json::array();
    for (const auto& c : contacts) {
        contacts_json.push_back({
            {"id", c.id},
            {"name", c.display_name},
            {"status", c.status},
            {"presence", c.presence},
            {"lastSeen", c.last_seen},
            {"unread", 0}
        });
    }
    return ipc::make_success({{"contacts", contacts_json}});
}

json MessageHandler::handle_chat_add_contact(const json& payload) {
    std::string session_id = payload.value("sessionId", "");
    std::string display_name = payload.value("displayName", "");
    if (session_id.empty()) {
        return ipc::make_error("sessionId_required");
    }

    ChatContact contact;
    contact.id = session_id;
    contact.display_name = display_name.empty() ? session_id : display_name;
    contact.status = "pending";
    contact.presence = "offline";
    chat_manager_->add_contact(contact);
    chat_manager_->save_contacts();

    return ipc::make_success({{"contactId", session_id}, {"status", "pending"}});
}

json MessageHandler::handle_chat_approve_contact(const json& payload) {
    std::string session_id = payload.value("sessionId", "");
    if (session_id.empty()) {
        return ipc::make_error("sessionId_required");
    }
    chat_manager_->approve_contact(session_id);
    chat_manager_->save_contacts();
    return ipc::make_success({{"contactId", session_id}, {"status", "approved"}});
}

json MessageHandler::handle_chat_reject_contact(const json& payload) {
    std::string session_id = payload.value("sessionId", "");
    if (session_id.empty()) {
        return ipc::make_error("sessionId_required");
    }
    chat_manager_->reject_contact(session_id);
    chat_manager_->save_contacts();
    return ipc::make_success({{"contactId", session_id}, {"status", "rejected"}});
}

json MessageHandler::handle_chat_get_messages(const json& payload) {
    int limit = payload.value("limit", 100);
    std::string conversation_id = payload.value("conversationId", "");
    int64_t before = payload.value("before", int64_t(0));

    std::vector<ChatMessage> messages_list;
    if (!conversation_id.empty()) {
        messages_list = chat_manager_->get_conversation_messages(
            conversation_id, limit, before);
    } else {
        messages_list = chat_manager_->get_history(limit);
    }

    json messages = json::array();
    for (const auto& msg : messages_list) {
        messages.push_back({
            {"id", msg.id},
            {"conversationId", msg.conversation_id},
            {"from", msg.sender_id},
            {"to", msg.recipient_id},
            {"text", msg.content},
            {"timestamp", msg.timestamp},
            {"read", msg.read},
            {"encrypted", msg.is_encrypted}
        });
    }
    return ipc::make_success({{"messages", messages}});
}

json MessageHandler::handle_chat_send_message(const json& payload) {
    std::string body = payload.value("body", "");
    std::string recipient_session_id = payload.value("recipientSessionId", "");

    if (body.empty()) {
        return ipc::make_error("body_required");
    }
    if (recipient_session_id.empty()) {
        return ipc::make_error("recipientSessionId_required");
    }

    // Store the message locally
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    ChatMessage msg;
    msg.sender_id = "self";
    msg.recipient_id = recipient_session_id;
    msg.conversation_id = "conv_" + recipient_session_id;
    msg.content = body;
    msg.timestamp = now;
    msg.read = true;
    msg.is_encrypted = false;
    chat_manager_->store_message(msg);
    chat_manager_->save_messages();

    // Try to encrypt if we have the recipient's public key
    auto* contact = chat_manager_->get_contact(recipient_session_id);
    json encrypted_payload = nullptr;
    if (contact && !contact->public_key_b64.empty()) {
        auto key_result = ShieldCrypt::decode_base64(contact->public_key_b64);
        if (key_result.ok()) {
            auto send_result = chat_manager_->send_message(body, key_result.value());
            if (send_result.ok()) {
                auto& enc = send_result.value();
                encrypted_payload = {
                    {"ciphertext_b64", ShieldCrypt::encode_base64(enc.ciphertext)},
                    {"nonce_b64", ShieldCrypt::encode_base64(enc.nonce)}
                };
            }
        }
    }

    // Emit sent event to renderer
    if (event_bridge_) {
        event_bridge_->push("chat_message_sent", {
            {"id", msg.id},
            {"recipientSessionId", recipient_session_id},
            {"body", body},
            {"timestamp", now},
        });
    }

    return ipc::make_success({
        {"sent", true},
        {"messageId", msg.id},
        {"timestamp", now},
        {"encrypted", encrypted_payload},
    });
}

json MessageHandler::handle_chat_mark_read(const json& payload) {
    std::string conversation_id = payload.value("conversationId", "");
    if (conversation_id.empty()) {
        return ipc::make_error("conversationId_required");
    }
    chat_manager_->mark_conversation_read(conversation_id);
    chat_manager_->save_messages();
    return ipc::make_success({{"conversationId", conversation_id}, {"marked", true}});
}

json MessageHandler::handle_chat_get_status(const json& /*payload*/) {
    return ipc::make_success({{"status", "connected"}});
}

json MessageHandler::handle_chat_set_presence(const json& payload) {
    std::string status = payload.value("status", "online");
    chat_manager_->set_presence(status);
    return ipc::make_success({{"presence", status}});
}

json MessageHandler::handle_upload_files(const json& /*payload*/) {
    if (!ui_client_) return ipc::make_error("no_ui_client");
    auto path = ui_client_->open_file_dialog("Select File", "");
    if (path.empty()) {
        return ipc::make_success({{"cancelled", true}});
    }

    // Read the file into memory
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return ipc::make_error("Failed to open file: " + path);
    }
    auto size = file.tellg();
    if (size <= 0) {
        return ipc::make_error("File is empty");
    }
    file.seekg(0);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(data.data()), size);

    // Extract filename from path
    std::string filename = path;
    auto last_sep = path.find_last_of("/\\");
    if (last_sep != std::string::npos) {
        filename = path.substr(last_sep + 1);
    }

    // Detect MIME type from extension
    std::string fn_lower = filename;
    for (auto& c : fn_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    std::string mime = "application/octet-stream";
    if (fn_lower.ends_with(".pdf")) mime = "application/pdf";
    else if (fn_lower.ends_with(".exe") || fn_lower.ends_with(".dll")) mime = "application/x-msdownload";
    else if (fn_lower.ends_with(".zip")) mime = "application/zip";
    else if (fn_lower.ends_with(".doc")) mime = "application/msword";
    else if (fn_lower.ends_with(".docx")) mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    else if (fn_lower.ends_with(".xls")) mime = "application/vnd.ms-excel";
    else if (fn_lower.ends_with(".xlsx")) mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    else if (fn_lower.ends_with(".ppt")) mime = "application/vnd.ms-powerpoint";
    else if (fn_lower.ends_with(".pptx")) mime = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    else if (fn_lower.ends_with(".eml") || fn_lower.ends_with(".msg")) mime = "message/rfc822";
    else if (fn_lower.ends_with(".png")) mime = "image/png";
    else if (fn_lower.ends_with(".jpg") || fn_lower.ends_with(".jpeg")) mime = "image/jpeg";
    else if (fn_lower.ends_with(".txt") || fn_lower.ends_with(".log") || fn_lower.ends_with(".csv")) mime = "text/plain";

    // Compute SHA256
    // Use OpenSSL/CommonCrypto for SHA256
    unsigned char hash[32]{};
#if defined(__APPLE__)
    CC_SHA256(data.data(), static_cast<CC_LONG>(data.size()), hash);
#elif defined(_WIN32)
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (hAlg) {
        BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        if (hHash) {
            BCryptHashData(hHash, data.data(), static_cast<ULONG>(data.size()), 0);
            BCryptFinishHash(hHash, hash, 32, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    unsigned int md_len = 0;
    EVP_DigestFinal_ex(ctx, hash, &md_len);
    EVP_MD_CTX_free(ctx);
#endif
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string sha256;
    sha256.reserve(64);
    for (auto byte : hash) {
        sha256.push_back(hex_chars[byte >> 4]);
        sha256.push_back(hex_chars[byte & 0x0f]);
    }

    // Store in captured files
    session_manager_->store_captured_file(sha256, std::move(data), filename, mime);

    // Emit download detected event
    if (event_bridge_) {
        event_bridge_->push_download_detected(sha256, filename, static_cast<size_t>(size));
    }

    // Auto-analyze
    auto_analyze(sha256);

    return ipc::make_success({
        {"filePath", path},
        {"sha256", sha256},
        {"filename", filename},
        {"fileSize", static_cast<int64_t>(size)},
    });
}

// handle_take_screenshot and handle_take_dom_snapshot are now handled
// inline in OnQuery with deferred CDP callbacks (see content_take_screenshot/
// content_take_dom_snapshot in ShieldTierClient).

// ── MITRE ATT&CK technique mapper ──
// Maps finding titles/keywords to MITRE technique IDs.
// Matches V1's approach where each engine tags findings with mitre IDs.
static std::string map_mitre_technique(const std::string& title,
                                        const std::string& engine_name) {
    std::string t = title;
    for (auto& c : t) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Process injection / hollowing
    if (t.find("inject") != std::string::npos || t.find("hollow") != std::string::npos)
        return "T1055";
    // Command & scripting interpreter
    if (t.find("script") != std::string::npos || t.find("powershell") != std::string::npos ||
        t.find("cmd") != std::string::npos || t.find("shell") != std::string::npos ||
        t.find("vbscript") != std::string::npos || t.find("wscript") != std::string::npos)
        return "T1059";
    // Obfuscation / packing
    if (t.find("obfuscat") != std::string::npos || t.find("pack") != std::string::npos ||
        t.find("encrypt") != std::string::npos || t.find("encode") != std::string::npos ||
        t.find("entropy") != std::string::npos)
        return "T1027";
    // Persistence — boot/logon autostart
    if (t.find("persist") != std::string::npos || t.find("autorun") != std::string::npos ||
        t.find("startup") != std::string::npos || t.find("autostart") != std::string::npos ||
        t.find("registry run") != std::string::npos)
        return "T1547";
    // Privilege escalation
    if (t.find("privilege") != std::string::npos || t.find("elevat") != std::string::npos ||
        t.find("uac") != std::string::npos)
        return "T1548";
    // Network communication / C2
    if (t.find("c2") != std::string::npos || t.find("beacon") != std::string::npos ||
        t.find("callback") != std::string::npos || t.find("command and control") != std::string::npos)
        return "T1071";
    // Data collection
    if (t.find("keylog") != std::string::npos || t.find("input capture") != std::string::npos ||
        t.find("credential") != std::string::npos || t.find("password") != std::string::npos)
        return "T1056";
    // System information discovery
    if (t.find("system info") != std::string::npos || t.find("discovery") != std::string::npos ||
        t.find("enumerat") != std::string::npos || t.find("fingerprint") != std::string::npos)
        return "T1082";
    // File/data collection
    if (t.find("collect") != std::string::npos || t.find("exfiltrat") != std::string::npos ||
        t.find("steal") != std::string::npos || t.find("harvest") != std::string::npos)
        return "T1005";
    // Ransomware / crypto
    if (t.find("ransom") != std::string::npos || t.find("crypto") != std::string::npos ||
        t.find("cipher") != std::string::npos)
        return "T1486";
    // Registry modification
    if (t.find("registry") != std::string::npos)
        return "T1112";
    // Service creation
    if (t.find("service") != std::string::npos || t.find("daemon") != std::string::npos)
        return "T1543";
    // Phishing
    if (t.find("phish") != std::string::npos || t.find("spear") != std::string::npos ||
        t.find("social engineer") != std::string::npos)
        return "T1566";
    // Suspicious network
    if (t.find("dns") != std::string::npos || t.find("domain") != std::string::npos ||
        t.find("url") != std::string::npos || t.find("http") != std::string::npos)
        return "T1071";
    // Suspicious imports / API
    if (t.find("import") != std::string::npos || t.find("api") != std::string::npos ||
        t.find("virtualalloc") != std::string::npos || t.find("createremotethread") != std::string::npos)
        return "T1106";
    // DLL side-loading / hijacking
    if (t.find("dll") != std::string::npos || t.find("sideload") != std::string::npos ||
        t.find("hijack") != std::string::npos)
        return "T1574";
    // Macro / office exploitation
    if (t.find("macro") != std::string::npos || t.find("ole") != std::string::npos ||
        t.find("vba") != std::string::npos)
        return "T1204.002";
    // PDF exploitation
    if (t.find("pdf") != std::string::npos && (t.find("javascript") != std::string::npos ||
        t.find("exploit") != std::string::npos || t.find("action") != std::string::npos))
        return "T1204.002";
    // Suspicious strings / indicators
    if (t.find("suspicious string") != std::string::npos ||
        t.find("suspicious url") != std::string::npos ||
        t.find("suspicious ip") != std::string::npos)
        return "T1071";
    // Evasion — anti-analysis
    if (t.find("anti-debug") != std::string::npos || t.find("anti-vm") != std::string::npos ||
        t.find("sandbox detect") != std::string::npos || t.find("evasion") != std::string::npos)
        return "T1497";
    // User execution
    if (t.find("user execution") != std::string::npos || t.find("lnk") != std::string::npos ||
        t.find("shortcut") != std::string::npos)
        return "T1204";

    // Engine-based defaults when no keyword match
    if (engine_name == "yara") return "T1027";  // YARA matches often indicate obfuscation/packing
    if (engine_name == "sandbox" || engine_name == "advanced") return "T1059";  // Behavioral = execution

    return "";  // No mapping
}

void MessageHandler::auto_analyze(const std::string& sha256) {
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        auto it = analysis_results_.find(sha256);
        if (it != analysis_results_.end()) {
            std::string status = it->second.value("status", "");
            if (status == "pending" || status == "complete") return;
        }
        analysis_results_[sha256] = {{"status", "pending"}};
    }

    auto* sm = session_manager_;
    auto* yara = yara_engine_.get();
    auto* fa = file_analyzer_.get();
    auto* em = enrichment_manager_.get();
    auto* sc = scoring_engine_.get();
    auto* sandbox = sandbox_engine_.get();
    auto* advanced = advanced_engine_.get();
    auto* email = email_analyzer_.get();
    auto* content = content_analyzer_.get();
    auto* log_mgr = log_manager_.get();
    auto* results_map = &analysis_results_;
    auto* mtx = &results_mutex_;
    auto* bridge = event_bridge_;

    std::jthread thread([sha256, sm, yara, fa, em, sc, sandbox, advanced,
                         email, content, log_mgr, results_map, mtx, bridge]
                        (std::stop_token stop) {
        auto file_opt = sm->get_captured_download(sha256);
        if (!file_opt.has_value()) {
            json err = {{"status", "error"}, {"error", "download_not_found"}};
            std::lock_guard<std::mutex> lock(*mtx);
            (*results_map)[sha256] = err;
            if (bridge) bridge->push_analysis_complete(sha256, err);
            return;
        }

        FileBuffer file = std::move(file_opt.value());
        std::vector<AnalysisEngineResult> engine_results;

        // YARA scan
        json yara_matches = json::array();
        if (stop.stop_requested()) return;
        auto yr = yara->scan(file);
        if (yr.ok()) {
            // Collect YARA match details for renderer
            for (const auto& f : yr.value().findings) {
                std::string mitre_id = f.metadata.value("mitre_technique", "");
                if (mitre_id.empty()) mitre_id = map_mitre_technique(f.title, "yara");
                json match = {
                    {"ruleName", f.title},
                    {"description", f.description},
                    {"severity", f.severity},
                    {"metadata", f.metadata}
                };
                if (!mitre_id.empty()) match["mitre"] = mitre_id;
                yara_matches.push_back(match);
            }
            engine_results.push_back(std::move(yr.value()));
        }

        // Static analysis
        json static_analysis = {
            {"fileType", ""}, {"mimeType", ""}, {"entropy", 0.0},
            {"findings", json::array()}, {"metadata", json::object()}
        };
        if (stop.stop_requested()) return;
        auto fr = fa->analyze(file);
        if (fr.ok()) {
            auto& fa_result = fr.value();
            // Extract static analysis fields from file analyzer output
            static_analysis["fileType"] = fa_result.raw_output.value("fileType", "");
            static_analysis["mimeType"] = fa_result.raw_output.value("mimeType", file.mime_type);
            static_analysis["entropy"] = fa_result.raw_output.value("entropy", 0.0);
            static_analysis["metadata"] = fa_result.raw_output.value("metadata", json::object());
            for (const auto& f : fa_result.findings) {
                std::string mitre_id = f.metadata.value("mitre_technique", "");
                if (mitre_id.empty()) mitre_id = map_mitre_technique(f.title, "file_analysis");
                json finding_j = {
                    {"title", f.title}, {"description", f.description},
                    {"severity", f.severity}, {"engine", f.engine}
                };
                if (!mitre_id.empty()) finding_j["mitre"] = mitre_id;
                static_analysis["findings"].push_back(finding_j);

                // Extract embedded URIs from PDF/document findings → register as IOCs
                if (f.metadata.contains("uris") && f.metadata["uris"].is_array() && bridge) {
                    for (const auto& uri : f.metadata["uris"]) {
                        std::string url_str = uri.get<std::string>();
                        if (!url_str.empty()) {
                            bridge->push("enrichment_result", {
                                {"value", url_str}, {"type", "url"},
                                {"source", "pdf_embedded"}, {"status", "pending"},
                                {"safe", false}, {"domain", ""},
                                {"firstSeen", std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch()).count()},
                                {"results", json::array()},
                            });
                        }
                    }
                }
            }
            engine_results.push_back(std::move(fa_result));
        }

        // Sandbox / behavioral analysis
        json sandbox_results = json::array();
        if (stop.stop_requested()) return;
        auto sr = sandbox->analyze(file);
        if (sr.ok()) {
            auto& sb_result = sr.value();
            // Build sandbox result entries for the renderer
            json sb_entry = {
                {"engine", sb_result.engine},
                {"score", 0},
                {"verdict", sb_result.success ? "clean" : "unknown"},
                {"findings", json::array()},
                {"duration_ms", sb_result.duration_ms},
            };
            int sb_score = 0;
            json sb_signatures = json::array();
            json sb_advanced_findings = json::array();
            for (const auto& f : sb_result.findings) {
                std::string mitre_id = f.metadata.value("mitre_technique", "");
                if (mitre_id.empty()) mitre_id = map_mitre_technique(f.title, "sandbox");
                json finding_j = {
                    {"title", f.title}, {"description", f.description},
                    {"severity", f.severity}, {"engine", f.engine},
                    {"metadata", f.metadata}, {"name", f.title},
                    {"evidence", json::array({f.description})},
                };
                if (!mitre_id.empty()) finding_j["mitre"] = mitre_id;
                sb_entry["findings"].push_back(finding_j);
                sb_signatures.push_back(finding_j);
                if (f.severity == Severity::kCritical) sb_score += 25;
                else if (f.severity == Severity::kHigh) sb_score += 15;
                else if (f.severity == Severity::kMedium) sb_score += 8;
                else if (f.severity == Severity::kLow) sb_score += 3;
            }
            if (sb_score > 100) sb_score = 100;
            sb_entry["score"] = sb_score;
            if (sb_score >= 70) sb_entry["verdict"] = "malicious";
            else if (sb_score >= 40) sb_entry["verdict"] = "suspicious";
            else if (sb_score > 0) sb_entry["verdict"] = "low_risk";
            if (!sb_result.raw_output.is_null()) {
                sb_entry["details"] = sb_result.raw_output;
            } else {
                sb_entry["details"] = json::object();
            }
            // Populate details.signatures and details.advancedFindings for MITRE panel
            sb_entry["details"]["signatures"] = sb_signatures;
            sb_entry["provider"] = "inline";
            sandbox_results.push_back(sb_entry);
            engine_results.push_back(std::move(sb_result));
        }

        if (stop.stop_requested()) return;
        auto ar = advanced->analyze(file);
        if (ar.ok()) {
            auto& adv_result = ar.value();
            // Advanced engine results also count as behavioral
            json adv_entry = {
                {"engine", adv_result.engine},
                {"score", 0},
                {"verdict", "clean"},
                {"findings", json::array()},
                {"duration_ms", adv_result.duration_ms},
            };
            int adv_score = 0;
            json adv_findings_arr = json::array();
            for (const auto& f : adv_result.findings) {
                std::string mitre_id = f.metadata.value("mitre_technique", "");
                if (mitre_id.empty()) mitre_id = map_mitre_technique(f.title, "advanced");
                json finding_j = {
                    {"title", f.title}, {"description", f.description},
                    {"severity", f.severity}, {"engine", f.engine},
                    {"metadata", f.metadata}, {"category", "advanced"},
                };
                if (!mitre_id.empty()) finding_j["mitre"] = mitre_id;
                adv_entry["findings"].push_back(finding_j);
                adv_findings_arr.push_back(finding_j);
                if (f.severity == Severity::kCritical) adv_score += 25;
                else if (f.severity == Severity::kHigh) adv_score += 15;
                else if (f.severity == Severity::kMedium) adv_score += 8;
                else if (f.severity == Severity::kLow) adv_score += 3;
            }
            if (adv_score > 100) adv_score = 100;
            adv_entry["score"] = adv_score;
            if (adv_score >= 70) adv_entry["verdict"] = "malicious";
            else if (adv_score >= 40) adv_entry["verdict"] = "suspicious";
            else if (adv_score > 0) adv_entry["verdict"] = "low_risk";
            if (!adv_result.raw_output.is_null()) {
                adv_entry["details"] = adv_result.raw_output;
            } else {
                adv_entry["details"] = json::object();
            }
            adv_entry["details"]["advancedFindings"] = adv_findings_arr;
            adv_entry["provider"] = "advanced";
            sandbox_results.push_back(adv_entry);
            engine_results.push_back(std::move(adv_result));
        }

        if (stop.stop_requested()) return;
        auto er = email->analyze(file);
        if (er.ok()) engine_results.push_back(std::move(er.value()));

        if (stop.stop_requested()) return;
        auto cr = content->analyze(file);
        if (cr.ok()) engine_results.push_back(std::move(cr.value()));

        if (stop.stop_requested()) return;
        auto lr = log_mgr->analyze(file);
        if (lr.ok()) engine_results.push_back(std::move(lr.value()));

        if (stop.stop_requested()) return;
        std::string md5 = FileAnalyzer::compute_md5(file.ptr(), file.size());
        std::string sha1 = FileAnalyzer::compute_sha1(file.ptr(), file.size());
        auto enr = em->enrich_by_hash(sha256, md5);
        json enrichment_data = json::object();
        if (enr.ok()) {
            enrichment_data = enr.value().raw_output;
            engine_results.push_back(std::move(enr.value()));
        }

        auto verdict_result = sc->score(engine_results);

        // Build full V1-compatible file result shape
        std::string risk_level = "info";
        json verdict_json;
        json output;
        if (verdict_result.ok()) {
            auto& v = verdict_result.value();
            verdict_json = v;  // uses NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE
            risk_level = v.risk_level;
            if (risk_level.empty()) {
                // Derive from verdict enum
                if (v.verdict == Verdict::kMalicious) risk_level = "critical";
                else if (v.verdict == Verdict::kSuspicious) risk_level = "high";
                else if (v.verdict == Verdict::kUnknown) risk_level = "medium";
                else risk_level = "info";
            }

            output = {
                {"status", "complete"},
                {"verdict", verdict_json},
                {"id", sha256},
                {"sha256", sha256},
                {"originalName", file.filename},
                {"fileSize", static_cast<int64_t>(file.size())},
                {"riskLevel", risk_level},
                {"hashes", {{"md5", md5}, {"sha1", sha1}, {"sha256", sha256}}},
                {"staticAnalysis", static_analysis},
                {"yaraMatches", yara_matches},
                {"sandboxResults", sandbox_results},
                {"enrichment", enrichment_data},
                {"behavioralAnalysisDone", true},
                {"behavioralAnalysisRunning", false},
            };
        } else {
            output = {
                {"status", "error"},
                {"error", verdict_result.error().message},
                {"id", sha256},
                {"sha256", sha256},
                {"originalName", file.filename},
                {"fileSize", static_cast<int64_t>(file.size())},
                {"riskLevel", "info"},
                {"hashes", {{"md5", md5}, {"sha1", sha1}, {"sha256", sha256}}},
                {"staticAnalysis", static_analysis},
                {"yaraMatches", yara_matches},
                {"sandboxResults", sandbox_results},
                {"enrichment", enrichment_data},
                {"behavioralAnalysisDone", true},
                {"behavioralAnalysisRunning", false},
            };
        }

        {
            std::lock_guard<std::mutex> lock(*mtx);
            (*results_map)[sha256] = output;
        }

        if (bridge) bridge->push_analysis_complete(sha256, output);
    });

    std::lock_guard<std::mutex> lock(threads_mutex_);
    analysis_threads_.push_back(std::move(thread));
}

// ═══════════════════════════════════════════════════════
// Auth Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::auth_api_post(const std::string& path, const json& body) {
    std::string url = std::string(kAuthApiUrl) + path;
    std::string body_str = body.dump();

    std::unordered_map<std::string, std::string> headers = {
        {"Accept", "application/json"},
    };

    // Add auth header for non-auth endpoints
    {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        if (!auth_access_token_.empty() &&
            path.find("/auth/") == std::string::npos) {
            headers["Authorization"] = "Bearer " + auth_access_token_;
        }
    }

    auto result = auth_http_->post_raw(url, body_str, headers);
    if (!result.ok()) {
        return json{{"success", false}, {"error", result.error().message}};
    }

    auto& resp = result.value();
    try {
        json parsed = json::parse(resp.body);
        if (resp.status_code >= 400) {
            std::string err = parsed.value("error", "HTTP " + std::to_string(resp.status_code));
            return json{{"success", false}, {"error", err}};
        }
        // Merge success flag if server doesn't include it
        if (!parsed.contains("success")) {
            parsed["success"] = true;
        }
        return parsed;
    } catch (...) {
        return json{{"success", false}, {"error", "Invalid server response"}};
    }
}

json MessageHandler::auth_api_get(const std::string& path) {
    std::string url = std::string(kAuthApiUrl) + path;

    std::unordered_map<std::string, std::string> headers = {
        {"Accept", "application/json"},
    };

    {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        if (!auth_access_token_.empty()) {
            headers["Authorization"] = "Bearer " + auth_access_token_;
        }
    }

    auto result = auth_http_->get_raw(url, headers);
    if (!result.ok()) {
        return json{{"success", false}, {"error", result.error().message}};
    }

    auto& resp = result.value();
    try {
        json parsed = json::parse(resp.body);
        if (resp.status_code >= 400) {
            std::string err = parsed.value("error", "HTTP " + std::to_string(resp.status_code));
            return json{{"success", false}, {"error", err}};
        }
        if (!parsed.contains("success")) {
            parsed["success"] = true;
        }
        return parsed;
    } catch (...) {
        return json{{"success", false}, {"error", "Invalid server response"}};
    }
}

void MessageHandler::auth_persist() {
    // Store tokens and user in config
    std::lock_guard<std::mutex> lock(auth_mutex_);
    config_store_->set("auth_access_token", auth_access_token_);
    config_store_->set("auth_refresh_token", auth_refresh_token_);
    config_store_->set("auth_token_expires_at", auth_token_expires_at_);
    if (!auth_user_.is_null()) {
        config_store_->set("auth_user", auth_user_);
    }
    config_store_->save();
}

void MessageHandler::auth_clear() {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    auth_access_token_.clear();
    auth_refresh_token_.clear();
    auth_token_expires_at_ = 0;
    auth_user_ = nullptr;
    config_store_->remove("auth_access_token");
    config_store_->remove("auth_refresh_token");
    config_store_->remove("auth_token_expires_at");
    config_store_->remove("auth_user");
    config_store_->save();
}

json MessageHandler::handle_auth_login(const json& payload) {
    // Dev bypass — skip cloud auth entirely
    if (is_dev_auth_enabled()) {
        auto user = make_dev_user();
        std::string email = payload.value("email", "");
        if (!email.empty()) user["email"] = email;
        {
            std::lock_guard<std::mutex> lock(auth_mutex_);
            auth_access_token_ = "dev-token";
            auth_refresh_token_ = "dev-refresh";
            auth_token_expires_at_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() + (86400 * 1000LL);
            auth_user_ = user;
        }
        auth_persist();
        fprintf(stderr, "[ShieldTier] Dev auth bypass — logged in as %s\n", user["email"].get<std::string>().c_str());
        return ipc::make_success({{"success", true}, {"user", user}});
    }

    std::string email = payload.value("email", "");
    std::string password = payload.value("password", "");

    if (email.empty() || password.empty()) {
        return ipc::make_success({{"success", false}, {"error", "Email and password are required"}});
    }

    auto res = auth_api_post("/auth/login", {{"email", email}, {"password", password}});

    if (!res.value("success", false)) {
        return ipc::make_success({{"success", false}, {"error", res.value("error", "Login failed")}});
    }

    // Extract tokens and user from server response
    json user_data;
    if (res.contains("user")) {
        user_data = res["user"];
    }
    if (res.contains("tokens")) {
        auto& tokens = res["tokens"];
        std::lock_guard<std::mutex> lock(auth_mutex_);
        auth_access_token_ = tokens.value("accessToken", "");
        auth_refresh_token_ = tokens.value("refreshToken", "");
        int expires_in = tokens.value("expiresIn", 3600);
        auth_token_expires_at_ = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() + (expires_in * 1000LL);
        auth_user_ = user_data;
    }

    auth_persist();

    return ipc::make_success({{"success", true}, {"user", user_data}});
}

json MessageHandler::handle_auth_register(const json& payload) {
    std::string email = payload.value("email", "");
    std::string password = payload.value("password", "");
    std::string analyst_name = payload.value("analystName", "");

    if (email.empty() || password.empty() || analyst_name.empty()) {
        return ipc::make_success({{"success", false}, {"error", "All fields are required"}});
    }
    if (password.size() < 8) {
        return ipc::make_success({{"success", false}, {"error", "Password must be at least 8 characters"}});
    }

    auto res = auth_api_post("/auth/register", {
        {"email", email}, {"password", password}, {"analystName", analyst_name}
    });

    if (!res.value("success", false)) {
        return ipc::make_success({{"success", false}, {"error", res.value("error", "Registration failed")}});
    }

    return ipc::make_success({{"success", true}, {"message", res.value("message", "Account created")}});
}

json MessageHandler::handle_auth_logout(const json& /*payload*/) {
    // Best-effort server-side logout
    {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        if (!auth_refresh_token_.empty()) {
            auth_api_post("/auth/logout", {{"refreshToken", auth_refresh_token_}});
        }
    }
    auth_clear();
    return ipc::make_success({{"success", true}});
}

json MessageHandler::handle_auth_get_user(const json& /*payload*/) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    if (auth_user_.is_null()) {
        return ipc::make_success(nullptr);
    }
    return ipc::make_success(auth_user_);
}

json MessageHandler::handle_auth_restore_session(const json& /*payload*/) {
    // Dev bypass — auto-restore fake session
    if (is_dev_auth_enabled()) {
        auto user = make_dev_user();
        {
            std::lock_guard<std::mutex> lock(auth_mutex_);
            auth_access_token_ = "dev-token";
            auth_refresh_token_ = "dev-refresh";
            auth_token_expires_at_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() + (86400 * 1000LL);
            auth_user_ = user;
        }
        fprintf(stderr, "[ShieldTier] Dev auth bypass — auto-restored session\n");
        return ipc::make_success({{"success", true}, {"user", user}});
    }

    // Load stored tokens from config
    auto stored_token = config_store_->get("auth_access_token");
    auto stored_refresh = config_store_->get("auth_refresh_token");
    auto stored_expires = config_store_->get("auth_token_expires_at");
    auto stored_user = config_store_->get("auth_user");

    if (stored_token.is_null() || stored_refresh.is_null() ||
        !stored_token.is_string() || stored_token.get<std::string>().empty()) {
        return ipc::make_success({{"success", false}, {"error", "No stored session"}});
    }

    {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        auth_access_token_ = stored_token.get<std::string>();
        auth_refresh_token_ = stored_refresh.is_string() ? stored_refresh.get<std::string>() : "";
        auth_token_expires_at_ = stored_expires.is_number() ? stored_expires.get<int64_t>() : 0;
        if (!stored_user.is_null()) {
            auth_user_ = stored_user;
        }
    }

    // Check if token expired — try refresh
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (now > auth_token_expires_at_ - 60000) {
        // Try refresh
        std::string refresh;
        {
            std::lock_guard<std::mutex> lock(auth_mutex_);
            refresh = auth_refresh_token_;
        }

        auto res = auth_api_post("/auth/refresh", {{"refreshToken", refresh}});
        if (res.value("success", false) && res.contains("tokens")) {
            auto& tokens = res["tokens"];
            std::lock_guard<std::mutex> lock(auth_mutex_);
            auth_access_token_ = tokens.value("accessToken", "");
            auth_refresh_token_ = tokens.value("refreshToken", "");
            int expires_in = tokens.value("expiresIn", 3600);
            auth_token_expires_at_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() + (expires_in * 1000LL);
            if (res.contains("user")) {
                auth_user_ = res["user"];
            }
            auth_persist();
        } else {
            // Refresh failed (server unreachable or token revoked)
            // If we have a cached user, return it anyway so the UI isn't stuck
            std::lock_guard<std::mutex> lock(auth_mutex_);
            if (!auth_user_.is_null()) {
                fprintf(stderr, "[ShieldTier] Auth refresh failed but cached user available — returning cached session\n");
                return ipc::make_success({{"success", true}, {"user", auth_user_}, {"offline", true}});
            }
            auth_clear();
            return ipc::make_success({{"success", false}, {"error", "Session expired"}});
        }
    }

    std::lock_guard<std::mutex> lock(auth_mutex_);
    if (auth_user_.is_null()) {
        return ipc::make_success({{"success", true}});
    }
    return ipc::make_success({{"success", true}, {"user", auth_user_}});
}

json MessageHandler::handle_auth_change_password(const json& payload) {
    std::string current = payload.value("currentPassword", "");
    std::string newpw = payload.value("newPassword", "");
    if (current.empty() || newpw.empty()) {
        return ipc::make_success({{"success", false}, {"error", "Both passwords required"}});
    }

    auto res = auth_api_post("/user/change-password", {
        {"currentPassword", current}, {"newPassword", newpw}
    });

    if (res.value("success", false)) {
        auth_clear();
        return ipc::make_success({{"success", true}});
    }
    return ipc::make_success({{"success", false}, {"error", res.value("error", "Password change failed")}});
}

json MessageHandler::handle_auth_resend_verification(const json& /*payload*/) {
    auto res = auth_api_post("/auth/resend-verification", json::object());
    return ipc::make_success({{"success", true}, {"message", res.value("message", "Verification email sent")}});
}

json MessageHandler::handle_auth_refresh_profile(const json& /*payload*/) {
    if (is_dev_auth_enabled()) {
        auto user = make_dev_user();
        return ipc::make_success({{"success", true}, {"user", user}});
    }
    auto res = auth_api_get("/user/profile");
    if (res.contains("id")) {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        auth_user_ = {
            {"id", res.value("id", "")},
            {"email", res.value("email", "")},
            {"analystName", res.value("analystName", "")},
            {"chatSessionId", res.value("chatSessionId", "")},
            {"avatar", res.value("avatar", nullptr)},
            {"emailVerified", res.value("emailVerified", false)},
        };
        config_store_->set("auth_user", auth_user_);
        config_store_->save();
        return ipc::make_success({{"success", true}, {"user", auth_user_}});
    }
    return ipc::make_success({{"success", false}, {"error", "Failed to refresh profile"}});
}

json MessageHandler::handle_auth_update_profile(const json& payload) {
    // Use POST as workaround (no PATCH in HttpClient yet)
    auto res = auth_api_post("/user/profile", payload);
    if (res.contains("id")) {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        auth_user_ = {
            {"id", res.value("id", "")},
            {"email", res.value("email", "")},
            {"analystName", res.value("analystName", "")},
            {"chatSessionId", res.value("chatSessionId", "")},
            {"avatar", res.value("avatar", nullptr)},
            {"emailVerified", res.value("emailVerified", false)},
        };
        config_store_->set("auth_user", auth_user_);
        config_store_->save();
        return ipc::make_success({{"success", true}, {"user", auth_user_}});
    }
    return ipc::make_success({{"success", false}, {"error", "Failed to update profile"}});
}

json MessageHandler::handle_auth_sync_cases(const json& payload) {
    auto cases = payload.value("cases", json::array());
    for (const auto& c : cases) {
        auth_api_post("/user/cases/sync", c);
    }
    return ipc::make_success({{"success", true}});
}

json MessageHandler::handle_auth_get_cases(const json& /*payload*/) {
    auto res = auth_api_get("/user/cases");
    return ipc::make_success({{"success", true}, {"cases", res.value("cases", json::array())}});
}

json MessageHandler::handle_auth_set_sync_key(const json& payload) {
    std::string sync_key = payload.value("syncKey", "");
    if (sync_key.empty()) {
        return ipc::make_success({{"success", false}, {"error", "Sync key required"}});
    }
    auto res = auth_api_post("/user/sync-key", {{"keyHash", sync_key}});
    if (res.value("success", false)) {
        return ipc::make_success({{"success", true}, {"syncToken", res.value("syncToken", "")}});
    }
    return ipc::make_success({{"success", false}, {"error", res.value("error", "Failed to set sync key")}});
}

// ═══════════════════════════════════════════════════════
// View / Nav State Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_get_nav_state(const json& /*payload*/) {
    if (!ui_client_) {
        return ipc::make_success({
            {"url", ""}, {"canGoBack", false},
            {"canGoForward", false}, {"isLoading", false}
        });
    }
    auto browser = ui_client_->content_browser();
    if (!browser) {
        return ipc::make_success({
            {"url", ""}, {"canGoBack", false},
            {"canGoForward", false}, {"isLoading", false}
        });
    }
    auto frame = browser->GetMainFrame();
    std::string url = frame ? frame->GetURL().ToString() : "";
    return ipc::make_success({
        {"url", url},
        {"canGoBack", browser->CanGoBack()},
        {"canGoForward", browser->CanGoForward()},
        {"isLoading", browser->IsLoading()}
    });
}

json MessageHandler::handle_analyze_now(const json& payload) {
    std::string session_id = payload.value("sessionId", "");
    // Trigger inline sandbox analysis on the currently loaded page
    if (ui_client_) {
        auto browser = ui_client_->content_browser();
        if (browser) {
            auto frame = browser->GetMainFrame();
            if (frame) {
                std::string url = frame->GetURL().ToString();
                // Use the sandbox engine to analyze the URL content
                if (event_bridge_) {
                    event_bridge_->push("sandbox_result", {
                        {"sessionId", session_id},
                        {"status", "started"},
                        {"url", url}
                    });
                }
                return ipc::make_success({{"status", "analysis_started"}, {"url", url}});
            }
        }
    }
    return ipc::make_error("no_content_browser");
}

// ═══════════════════════════════════════════════════════
// Config: Whitelist Check
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_check_whitelist(const json& payload) {
    std::string domain = payload.value("domain", "");
    if (domain.empty()) {
        return ipc::make_error("domain_required");
    }
    auto whitelist = config_store_->get("whitelist");
    if (whitelist.is_array()) {
        for (const auto& entry : whitelist) {
            if (entry.is_string()) {
                std::string pattern = entry.get<std::string>();
                // Exact match or wildcard suffix match (*.example.com)
                if (pattern == domain) {
                    return ipc::make_success({{"whitelisted", true}});
                }
                if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.') {
                    std::string suffix = pattern.substr(1);  // .example.com
                    if (domain.size() >= suffix.size() &&
                        domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0) {
                        return ipc::make_success({{"whitelisted", true}});
                    }
                }
            }
        }
    }
    return ipc::make_success({{"whitelisted", false}});
}

// ═══════════════════════════════════════════════════════
// YARA Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_yara_get_rules(const json& /*payload*/) {
    auto rules = yara_engine_->rule_manager().get_all_rules();
    json rules_json = json::array();
    for (const auto& r : rules) {
        rules_json.push_back({
            {"name", r.name}, {"source", r.source}, {"origin", r.origin}
        });
    }
    return ipc::make_success({{"rules", rules_json}, {"count", rules.size()}});
}

json MessageHandler::handle_yara_get_rule(const json& payload) {
    std::string id = payload.value("id", "");
    if (id.empty()) return ipc::make_error("id_required");

    auto rules = yara_engine_->rule_manager().get_all_rules();
    for (const auto& r : rules) {
        if (r.name == id) {
            return ipc::make_success({
                {"name", r.name}, {"source", r.source}, {"origin", r.origin}
            });
        }
    }
    return ipc::make_error("rule_not_found");
}

json MessageHandler::handle_yara_add_rule(const json& payload) {
    std::string name = payload.value("name", "");
    std::string source = payload.value("source", "");
    if (name.empty() || source.empty()) {
        return ipc::make_error("name_and_source_required");
    }
    auto result = yara_engine_->rule_manager().add_rule(name, source, "custom");
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }
    yara_engine_->compile_rules();
    return ipc::make_success({{"name", name}});
}

json MessageHandler::handle_yara_update_rule(const json& payload) {
    std::string id = payload.value("id", "");
    auto rule = payload.value("rule", json::object());
    std::string name = rule.value("name", id);
    std::string source = rule.value("source", "");
    if (name.empty() || source.empty()) {
        return ipc::make_error("name_and_source_required");
    }
    // RuleManager has no delete — add overwrites by re-adding with same name
    auto result = yara_engine_->rule_manager().add_rule(name, source, "custom");
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }
    yara_engine_->compile_rules();
    return ipc::make_success({{"name", name}});
}

json MessageHandler::handle_yara_delete_rule(const json& payload) {
    std::string id = payload.value("id", "");
    if (id.empty()) return ipc::make_error("id_required");
    // Mark as deleted in config (RuleManager doesn't support delete)
    auto deleted = config_store_->get("yara_deleted_rules");
    if (!deleted.is_array()) deleted = json::array();
    deleted.push_back(id);
    config_store_->set("yara_deleted_rules", deleted);
    config_store_->save();
    return ipc::make_success({{"deleted", id}});
}

json MessageHandler::handle_yara_import_rules(const json& payload) {
    auto data = payload.value("data", "");
    if (data.empty()) return ipc::make_error("data_required");

    // Treat data as a single rule source blob — add as "imported"
    auto result = yara_engine_->rule_manager().add_rule("imported_" + std::to_string(
        std::chrono::system_clock::now().time_since_epoch().count()), data, "imported");
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }
    yara_engine_->compile_rules();
    return ipc::make_success({{"imported", true}});
}

json MessageHandler::handle_yara_export_rules(const json& /*payload*/) {
    auto rules = yara_engine_->rule_manager().get_all_rules();
    json rules_json = json::array();
    for (const auto& r : rules) {
        rules_json.push_back({
            {"name", r.name}, {"source", r.source}, {"origin", r.origin}
        });
    }
    return ipc::make_success({{"rules", rules_json}});
}

json MessageHandler::handle_yara_get_packs(const json& /*payload*/) {
    auto rules = yara_engine_->rule_manager().get_all_rules();
    // Group by origin to build packs
    std::unordered_map<std::string, int> pack_counts;
    for (const auto& r : rules) {
        pack_counts[r.origin]++;
    }
    auto disabled = config_store_->get("yara_disabled_packs");
    json packs = json::array();
    for (const auto& [origin, count] : pack_counts) {
        bool enabled = true;
        if (disabled.is_array()) {
            for (const auto& d : disabled) {
                if (d.is_string() && d.get<std::string>() == origin) {
                    enabled = false;
                    break;
                }
            }
        }
        packs.push_back({{"name", origin}, {"ruleCount", count}, {"enabled", enabled}});
    }
    return ipc::make_success({{"packs", packs}});
}

json MessageHandler::handle_yara_toggle_pack(const json& payload) {
    std::string pack = payload.value("pack", "");
    bool enabled = payload.value("enabled", true);
    if (pack.empty()) return ipc::make_error("pack_required");

    auto disabled = config_store_->get("yara_disabled_packs");
    if (!disabled.is_array()) disabled = json::array();

    if (enabled) {
        // Remove from disabled list
        json new_disabled = json::array();
        for (const auto& d : disabled) {
            if (d.is_string() && d.get<std::string>() != pack) {
                new_disabled.push_back(d);
            }
        }
        disabled = new_disabled;
    } else {
        // Add to disabled list
        bool already = false;
        for (const auto& d : disabled) {
            if (d.is_string() && d.get<std::string>() == pack) { already = true; break; }
        }
        if (!already) disabled.push_back(pack);
    }

    config_store_->set("yara_disabled_packs", disabled);
    config_store_->save();
    return ipc::make_success({{"pack", pack}, {"enabled", enabled}});
}

json MessageHandler::handle_yara_scan_file(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) return ipc::make_error("sha256_required");

    auto file_opt = session_manager_->get_captured_download(sha256);
    if (!file_opt.has_value()) return ipc::make_error("download_not_found");

    auto result = yara_engine_->scan(file_opt.value());
    if (!result.ok()) return ipc::make_error(result.error().message);

    auto& r = result.value();
    json findings_json = json::array();
    for (const auto& f : r.findings) {
        findings_json.push_back({
            {"title", f.title}, {"description", f.description},
            {"severity", f.severity}, {"engine", f.engine}, {"metadata", f.metadata}
        });
    }
    return ipc::make_success({
        {"engine", "yara"}, {"findings", findings_json}, {"duration_ms", r.duration_ms}
    });
}

json MessageHandler::handle_yara_scan_content(const json& payload) {
    std::string content = payload.value("content", "");
    if (content.empty()) return ipc::make_error("content_required");

    FileBuffer buf;
    buf.data.assign(content.begin(), content.end());
    buf.filename = "content_scan";
    buf.mime_type = "text/plain";
    auto result = yara_engine_->scan(buf);
    if (!result.ok()) return ipc::make_error(result.error().message);

    auto& r = result.value();
    json findings_json = json::array();
    for (const auto& f : r.findings) {
        findings_json.push_back({
            {"title", f.title}, {"description", f.description},
            {"severity", f.severity}, {"engine", f.engine}, {"metadata", f.metadata}
        });
    }
    return ipc::make_success({
        {"engine", "yara"}, {"findings", findings_json}, {"duration_ms", r.duration_ms}
    });
}

json MessageHandler::handle_yara_get_results(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) return ipc::make_error("sha256_required");

    std::lock_guard<std::mutex> lock(results_mutex_);
    auto it = analysis_results_.find(sha256);
    if (it == analysis_results_.end()) {
        return ipc::make_success({{"status", "not_found"}});
    }
    // Extract YARA-specific findings from the verdict if available
    return ipc::make_success(it->second);
}

// ═══════════════════════════════════════════════════════
// File Analysis: Delete, Archive Password
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_delete_file(const json& payload) {
    std::string file_id = payload.value("fileId", "");
    if (file_id.empty()) return ipc::make_error("fileId_required");

    // Remove from analysis results cache
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        analysis_results_.erase(file_id);
    }
    return ipc::make_success({{"deleted", file_id}});
}

json MessageHandler::handle_submit_archive_password(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    std::string password = payload.value("password", "");
    if (sha256.empty()) return ipc::make_error("sha256_required");

    // Store password in-memory only (NOT persisted to disk — security)
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        analysis_results_["archive_pw_" + sha256] = json{{"password", password}};
    }
    // Re-trigger analysis pipeline with the password available
    auto file_opt = session_manager_->get_captured_download(sha256);
    if (file_opt.has_value()) {
        auto_analyze(sha256);
        return ipc::make_success({{"status", "reanalyzing"}, {"sha256", sha256}});
    }
    return ipc::make_error("download_not_found");
}

json MessageHandler::handle_skip_archive_password(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) return ipc::make_error("sha256_required");
    // Mark as skipped in-memory only
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        analysis_results_["archive_pw_" + sha256] = json{{"password", "__skipped__"}};
    }
    return ipc::make_success({{"status", "skipped"}, {"sha256", sha256}});
}

// ═══════════════════════════════════════════════════════
// Email Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_get_emails(const json& /*payload*/) {
    // Return all parsed email results from analysis cache.
    // Emails are stored with key "email_<timestamp>" and contain fields
    // like "from", "subject", "phishingScore" — NOT an "engine" field.
    std::lock_guard<std::mutex> lock(results_mutex_);
    json emails = json::array();
    for (const auto& [key, result] : analysis_results_) {
        // Email entries have an "id" starting with "email_" and contain "from"
        if (key.compare(0, 6, "email_") == 0 && result.contains("from")) {
            emails.push_back(result);
        }
    }
    return ipc::make_success({{"emails", emails}});
}

json MessageHandler::handle_get_email(const json& payload) {
    std::string email_id = payload.value("emailId", "");
    if (email_id.empty()) return ipc::make_error("emailId_required");

    std::lock_guard<std::mutex> lock(results_mutex_);
    auto it = analysis_results_.find(email_id);
    if (it != analysis_results_.end()) {
        return ipc::make_success(it->second);
    }
    return ipc::make_error("email_not_found");
}

json MessageHandler::handle_open_email_file(const json& payload) {
    if (!ui_client_) return ipc::make_error("no_ui_client");
    auto path = ui_client_->open_file_dialog("Open Email", "eml,msg,txt,mhtml");
    if (path.empty()) {
        return ipc::make_success({{"cancelled", true}});
    }

    // Read the file content
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return ipc::make_error("Failed to open file: " + path);
    }
    auto size = file.tellg();
    file.seekg(0);
    std::string content(static_cast<size_t>(size), '\0');
    file.read(content.data(), size);

    // Parse it through the email analyzer
    std::string session_id = payload.value("sessionId", "");
    json parse_payload = {{"rawSource", content}, {"sessionId", session_id}};
    return handle_analyze_email(parse_payload);
}

// ═══════════════════════════════════════════════════════
// Chat: New Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_chat_remove_contact(const json& payload) {
    std::string contact_id = payload.value("contactId", "");
    if (contact_id.empty()) return ipc::make_error("contactId_required");
    chat_manager_->remove_contact(contact_id);
    chat_manager_->save_contacts();
    return ipc::make_success({{"removed", contact_id}});
}

json MessageHandler::handle_chat_update_contact(const json& payload) {
    std::string contact_id = payload.value("contactId", "");
    std::string name = payload.value("name", "");
    if (contact_id.empty()) return ipc::make_error("contactId_required");
    chat_manager_->update_contact_name(contact_id, name);
    chat_manager_->save_contacts();
    return ipc::make_success({{"contactId", contact_id}, {"name", name}});
}

json MessageHandler::handle_chat_get_conversations(const json& /*payload*/) {
    auto convos = chat_manager_->get_conversations();
    json result = json::array();
    for (const auto& c : convos) {
        result.push_back({
            {"id", c.id},
            {"contactId", c.contact_id},
            {"lastMessage", c.last_message},
            {"lastTimestamp", c.last_timestamp},
            {"unreadCount", c.unread_count}
        });
    }
    return ipc::make_success({{"conversations", result}});
}

json MessageHandler::handle_chat_lookup_user(const json& payload) {
    std::string query = payload.value("query", "");
    if (query.empty()) return ipc::make_error("query_required");

    // Server-side lookup via auth API
    auto res = auth_api_get("/users/lookup?q=" + query);
    if (res.value("success", false)) {
        return ipc::make_success({{"users", res.value("users", json::array())}});
    }
    return ipc::make_success({{"users", json::array()}});
}

json MessageHandler::handle_chat_ack_onboarding(const json& /*payload*/) {
    config_store_->set("chat_onboarding_done", true);
    config_store_->save();
    return ipc::make_success({{"acknowledged", true}});
}

json MessageHandler::handle_chat_get_requests(const json& /*payload*/) {
    auto requests = config_store_->get("chat_message_requests");
    if (!requests.is_array()) requests = json::array();
    return ipc::make_success({{"requests", requests}});
}

// ═══════════════════════════════════════════════════════
// Threat Feed Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_threatfeed_add(const json& payload) {
    std::string name = payload.value("name", "");
    std::string url = payload.value("url", "");
    if (name.empty() || url.empty()) return ipc::make_error("name_and_url_required");

    auto feeds = config_store_->get("threat_feeds");
    if (!feeds.is_array()) feeds = json::array();

    std::string feed_id = "feed_" + std::to_string(feeds.size() + 1);
    json feed = {
        {"id", feed_id}, {"name", name}, {"url", url},
        {"enabled", true}, {"type", payload.value("type", "csv")},
        {"lastSync", nullptr}
    };
    feeds.push_back(feed);
    config_store_->set("threat_feeds", feeds);
    config_store_->save();

    // Trigger feed update
    threat_feed_manager_->update_feeds();
    return ipc::make_success(feed);
}

json MessageHandler::handle_threatfeed_update(const json& payload) {
    std::string feed_id = payload.value("feedId", "");
    auto updates = payload.value("updates", json::object());
    if (feed_id.empty()) return ipc::make_error("feedId_required");

    auto feeds = config_store_->get("threat_feeds");
    if (!feeds.is_array()) return ipc::make_error("no_feeds");

    for (auto& f : feeds) {
        if (f.value("id", "") == feed_id) {
            f.merge_patch(updates);
            config_store_->set("threat_feeds", feeds);
            config_store_->save();
            return ipc::make_success(f);
        }
    }
    return ipc::make_error("feed_not_found");
}

json MessageHandler::handle_threatfeed_delete(const json& payload) {
    std::string feed_id = payload.value("feedId", "");
    if (feed_id.empty()) return ipc::make_error("feedId_required");

    auto feeds = config_store_->get("threat_feeds");
    if (!feeds.is_array()) return ipc::make_error("no_feeds");

    json filtered = json::array();
    for (const auto& f : feeds) {
        if (f.value("id", "") != feed_id) {
            filtered.push_back(f);
        }
    }
    config_store_->set("threat_feeds", filtered);
    config_store_->save();
    return ipc::make_success({{"deleted", feed_id}});
}

json MessageHandler::handle_threatfeed_toggle(const json& payload) {
    std::string feed_id = payload.value("feedId", "");
    bool enabled = payload.value("enabled", true);
    if (feed_id.empty()) return ipc::make_error("feedId_required");

    auto feeds = config_store_->get("threat_feeds");
    if (!feeds.is_array()) return ipc::make_error("no_feeds");

    for (auto& f : feeds) {
        if (f.value("id", "") == feed_id) {
            f["enabled"] = enabled;
            config_store_->set("threat_feeds", feeds);
            config_store_->save();
            return ipc::make_success({{"feedId", feed_id}, {"enabled", enabled}});
        }
    }
    return ipc::make_error("feed_not_found");
}

json MessageHandler::handle_threatfeed_discover(const json& /*payload*/) {
    // Return a curated list of public threat feed sources
    json sources = json::array();
    sources.push_back({{"name", "abuse.ch URLhaus"}, {"url", "https://urlhaus.abuse.ch/downloads/csv_recent/"}, {"type", "csv"}});
    sources.push_back({{"name", "abuse.ch Feodo Tracker"}, {"url", "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"}, {"type", "csv"}});
    sources.push_back({{"name", "abuse.ch ThreatFox IOCs"}, {"url", "https://threatfox.abuse.ch/export/csv/recent/"}, {"type", "csv"}});
    sources.push_back({{"name", "AlienVault OTX Pulse"}, {"url", "https://otx.alienvault.com/api/v1/pulses/subscribed"}, {"type", "stix"}});
    sources.push_back({{"name", "Emerging Threats"}, {"url", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"}, {"type", "csv"}});
    return ipc::make_success({{"sources", sources}});
}

json MessageHandler::handle_threatfeed_collections(const json& /*payload*/) {
    auto feeds = config_store_->get("threat_feeds");
    if (!feeds.is_array()) feeds = json::array();
    return ipc::make_success({{"collections", feeds}});
}

json MessageHandler::handle_threatfeed_sync(const json& payload) {
    std::string feed_id = payload.value("feedId", "");
    if (feed_id.empty()) return ipc::make_error("feedId_required");

    // Trigger sync in background
    threat_feed_manager_->update_feeds();

    // Update lastSync timestamp
    auto feeds = config_store_->get("threat_feeds");
    if (feeds.is_array()) {
        for (auto& f : feeds) {
            if (f.value("id", "") == feed_id) {
                f["lastSync"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                break;
            }
        }
        config_store_->set("threat_feeds", feeds);
        config_store_->save();
    }

    if (event_bridge_) {
        event_bridge_->push("threatfeed_sync_status", {{"feedId", feed_id}, {"status", "syncing"}});
    }
    return ipc::make_success({{"status", "syncing"}, {"feedId", feed_id}});
}

json MessageHandler::handle_threatfeed_sync_all(const json& /*payload*/) {
    threat_feed_manager_->update_feeds();

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto feeds = config_store_->get("threat_feeds");
    if (feeds.is_array()) {
        for (auto& f : feeds) {
            if (f.value("enabled", true)) {
                f["lastSync"] = now;
            }
        }
        config_store_->set("threat_feeds", feeds);
        config_store_->save();
    }

    if (event_bridge_) {
        event_bridge_->push("threatfeed_sync_status", {{"status", "syncing_all"}});
    }
    return ipc::make_success({{"status", "syncing_all"}});
}

json MessageHandler::handle_threatfeed_matches(const json& payload) {
    std::string session_id = payload.value("sessionId", "");
    // Look up analysis results and check IOCs against threat feeds
    json matches = json::array();

    std::lock_guard<std::mutex> lock(results_mutex_);
    for (const auto& [sha256, result] : analysis_results_) {
        if (threat_feed_manager_->is_known_threat("sha256", sha256)) {
            auto indicators = threat_feed_manager_->lookup("sha256", sha256);
            for (const auto& ind : indicators) {
                matches.push_back({
                    {"type", ind.type}, {"value", ind.value},
                    {"source", ind.source}, {"sha256", sha256}
                });
            }
        }
    }
    return ipc::make_success({{"matches", matches}});
}

json MessageHandler::handle_threatfeed_import_csv(const json& payload) {
    std::string data = payload.value("data", "");
    if (data.empty()) return ipc::make_error("data_required");

    // Parse CSV lines and add as custom indicators
    auto custom_iocs = config_store_->get("custom_threat_iocs");
    if (!custom_iocs.is_array()) custom_iocs = json::array();

    std::istringstream stream(data);
    std::string line;
    int count = 0;
    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == '#') continue;
        custom_iocs.push_back({{"value", line}, {"type", "unknown"}, {"source", "csv_import"}});
        count++;
    }
    config_store_->set("custom_threat_iocs", custom_iocs);
    config_store_->save();
    return ipc::make_success({{"imported", count}});
}

json MessageHandler::handle_threatfeed_import_stix(const json& payload) {
    std::string data = payload.value("data", "");
    if (data.empty()) return ipc::make_error("data_required");

    // Parse STIX JSON and extract indicators
    auto custom_iocs = config_store_->get("custom_threat_iocs");
    if (!custom_iocs.is_array()) custom_iocs = json::array();

    int count = 0;
    try {
        json stix = json::parse(data);
        auto objects = stix.value("objects", json::array());
        for (const auto& obj : objects) {
            if (obj.value("type", "") == "indicator") {
                std::string pattern = obj.value("pattern", "");
                custom_iocs.push_back({{"value", pattern}, {"type", "stix"}, {"source", "stix_import"}});
                count++;
            }
        }
    } catch (...) {
        return ipc::make_error("invalid_stix_json");
    }

    config_store_->set("custom_threat_iocs", custom_iocs);
    config_store_->save();
    return ipc::make_success({{"imported", count}});
}

json MessageHandler::handle_threatfeed_stats(const json& /*payload*/) {
    size_t total = threat_feed_manager_->indicator_count();
    auto feeds = config_store_->get("threat_feeds");

    json breakdown = json::object();
    if (feeds.is_array()) {
        for (const auto& f : feeds) {
            std::string name = f.value("name", "unknown");
            breakdown[name] = 0;  // Per-feed counts not available from engine
        }
    }

    auto custom_iocs = config_store_->get("custom_threat_iocs");
    int custom_count = custom_iocs.is_array() ? static_cast<int>(custom_iocs.size()) : 0;

    return ipc::make_success({
        {"totalIOCs", total + custom_count},
        {"engineIOCs", total},
        {"customIOCs", custom_count},
        {"feedBreakdown", breakdown}
    });
}

// ═══════════════════════════════════════════════════════
// VM Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_vm_get_status(const json& /*payload*/) {
    auto qemu_result = vm_installer_->find_qemu();
    bool installed = qemu_result.ok();

    auto vms = vm_manager_->list_vms();
    std::string status = "idle";
    if (!vms.empty()) {
        auto state = vm_manager_->get_state(vms.front().id);
        if (state == VmState::kBooting) status = "booting";
        else if (state == VmState::kReady) status = "ready";
        else if (state == VmState::kAnalyzing) status = "analyzing";
        else if (state == VmState::kError) status = "error";
    }

    std::string version;
    std::string accelerator = "tcg";
#if defined(__aarch64__) || defined(_M_ARM64)
    accelerator = "hvf";
#elif defined(__x86_64__) || defined(_M_X64)
    #ifdef __APPLE__
    accelerator = "hvf";
    #elif defined(__linux__)
    accelerator = "kvm";
    #else
    accelerator = "whpx";
    #endif
#endif

    if (installed) {
        auto qemu_path = qemu_result.value();
        std::string cmd = qemu_path + " --version 2>/dev/null";
#ifdef _WIN32
        cmd = "\"" + qemu_path + "\" --version 2>nul";
#endif
#ifdef _WIN32
        FILE* pipe = _popen(cmd.c_str(), "r");
#else
        FILE* pipe = popen(cmd.c_str(), "r");
#endif
        if (pipe) {
            char buf[256];
            if (fgets(buf, sizeof(buf), pipe)) {
                version = buf;
                auto pos = version.find("version ");
                if (pos != std::string::npos) {
                    version = version.substr(pos + 8);
                    auto end = version.find_first_of(" \n\r(");
                    if (end != std::string::npos) version = version.substr(0, end);
                }
            }
#ifdef _WIN32
            _pclose(pipe);
#else
            pclose(pipe);
#endif
        }
    }

    // Check Windows Sandbox availability.
    bool wsb_available = WindowsSandbox::is_available();
    std::string wsb_session;
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        wsb_session = active_wsb_session_;
    }
    if (!wsb_session.empty()) {
        auto wsb_state = windows_sandbox_->get_state(wsb_session);
        if (wsb_state == VmState::kBooting) status = "booting";
        else if (wsb_state == VmState::kReady) status = "ready";
        else if (wsb_state == VmState::kAnalyzing) status = "analyzing";
        else if (wsb_state == VmState::kError) status = "error";
    }

    return ipc::make_success({
        {"installed", installed || wsb_available}, {"status", status},
        {"activeInstances", vms.size() + (wsb_session.empty() ? 0 : 1)},
        {"version", version}, {"accelerator", accelerator},
        {"windows_sandbox_available", wsb_available},
        {"provider", wsb_available ? "windows_sandbox" : "qemu"}
    });
}

json MessageHandler::handle_vm_install(const json& /*payload*/) {
    // Check if already installed
    auto existing = vm_installer_->find_qemu();
    if (existing.ok()) {
        if (event_bridge_) {
            event_bridge_->push("vm_install_progress",
                                {{"status", "complete"}, {"progress", 100},
                                 {"log", "QEMU already installed at " + existing.value()}});
        }
        return ipc::make_success({{"status", "already_installed"}, {"path", existing.value()}});
    }

    // Run installation on background thread
    auto* event_bridge = event_bridge_;
    auto* installer = vm_installer_.get();

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        analysis_threads_.emplace_back([event_bridge, installer] {
            auto progress_cb = [event_bridge](const json& progress) {
                if (event_bridge) {
                    event_bridge->push("vm_install_progress", progress);
                }
            };

            installer->install_qemu(progress_cb);
        });
    }

    return ipc::make_success({{"status", "install_started"}});
}

json MessageHandler::handle_vm_list_images(const json& /*payload*/) {
    json images = json::array();

    // If Windows Sandbox is available, add a virtual image entry so the
    // existing React panel sees an already-downloaded image and shows the
    // "ready" view instead of the QEMU setup flow.
    if (WindowsSandbox::is_available()) {
        // Use 'reactos-0.4.15' as id so the panel's "Windows" button
        // (which hardcodes setSelectedImageId('reactos-0.4.15')) auto-selects it.
        images.push_back({
            {"id", "reactos-0.4.15"},
            {"name", "Windows Sandbox (built-in)"},
            {"os", "windows"},
            {"downloadSize", 0},
            {"diskSize", 0},
            {"downloaded", true},
            {"size", "Built-in"},
            {"provider", "windows_sandbox"}
        });
    }

    auto catalog = VmInstaller::default_image_catalog();
    for (const auto& spec : catalog) {
        double size_mb = static_cast<double>(spec.size_bytes) / (1024.0 * 1024.0);
        images.push_back({
            {"id", spec.id},
            {"name", spec.name},
            {"os", spec.os},
            {"downloadSize", spec.size_bytes},
            {"diskSize", spec.size_bytes * 2},  // estimate expanded size
            {"downloaded", vm_installer_->is_image_downloaded(spec.id)},
            {"size", std::to_string(static_cast<int>(size_mb)) + "MB"}
        });
    }
    return ipc::make_success({{"images", images}});
}

json MessageHandler::handle_vm_download_image(const json& payload) {
    std::string image_id = payload.value("imageId", "");
    if (image_id.empty()) return ipc::make_error("imageId_required");

    // Already downloaded?
    if (vm_installer_->is_image_downloaded(image_id)) {
        if (event_bridge_) {
            event_bridge_->push("vm_image_download_progress", {
                {"imageId", image_id}, {"status", "complete"}, {"progress", 100},
                {"downloadedMB", 0}, {"totalMB", 0}
            });
        }
        return ipc::make_success({{"status", "already_downloaded"}, {"imageId", image_id}});
    }

    // Find the image spec from catalog
    auto catalog = VmInstaller::default_image_catalog();
    const VmImageSpec* spec = nullptr;
    for (const auto& s : catalog) {
        if (s.id == image_id) {
            spec = &s;
            break;
        }
    }
    if (!spec) return ipc::make_error("unknown_image: " + image_id);

    // Reset cancel flag
    vm_download_cancel_.store(false);

    // Capture by value for thread safety
    VmImageSpec spec_copy = *spec;
    auto* event_bridge = event_bridge_;
    auto* installer = vm_installer_.get();
    auto* cancel = &vm_download_cancel_;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        analysis_threads_.emplace_back([event_bridge, installer, spec_copy, cancel] {
            auto progress_cb = [event_bridge](const json& progress) {
                if (event_bridge) {
                    event_bridge->push("vm_image_download_progress", progress);
                }
            };

            installer->download_image(spec_copy, progress_cb, *cancel);
        });
    }

    return ipc::make_success({{"status", "download_started"}, {"imageId", image_id}});
}

json MessageHandler::handle_vm_get_instances(const json& /*payload*/) {
    json instances = json::array();

    // Include Windows Sandbox sessions.
    if (windows_sandbox_) {
        auto wsb_sessions = windows_sandbox_->list_sessions();
        for (const auto& s : wsb_sessions) {
            std::string state_str = "unknown";
            if (s.state == VmState::kStopped) state_str = "stopped";
            else if (s.state == VmState::kBooting) state_str = "booting";
            else if (s.state == VmState::kReady) state_str = "ready";
            else if (s.state == VmState::kAnalyzing) state_str = "analyzing";
            else if (s.state == VmState::kError) state_str = "error";
            instances.push_back({
                {"id", s.id}, {"state", state_str}, {"provider", "windows_sandbox"}
            });
        }
    }

    // Include QEMU VMs.
    auto vms = vm_manager_->list_vms();
    for (const auto& vm : vms) {
        auto state = vm_manager_->get_state(vm.id);
        std::string state_str = "unknown";
        if (state == VmState::kStopped) state_str = "stopped";
        else if (state == VmState::kBooting) state_str = "booting";
        else if (state == VmState::kReady) state_str = "ready";
        else if (state == VmState::kAnalyzing) state_str = "analyzing";
        else if (state == VmState::kError) state_str = "error";
        instances.push_back({
            {"id", vm.id}, {"state", state_str}, {"provider", "qemu"}
        });
    }
    return ipc::make_success({{"instances", instances}});
}

json MessageHandler::handle_vm_get_result(const json& payload) {
    std::string instance_id = payload.value("instanceId", "");
    if (instance_id.empty()) {
        // Check Windows Sandbox sessions first.
        std::lock_guard<std::mutex> lock(threads_mutex_);
        if (!active_wsb_session_.empty()) {
            instance_id = active_wsb_session_;
        }
    }
    if (instance_id.empty()) {
        auto vms = vm_manager_->list_vms();
        if (!vms.empty()) instance_id = vms.front().id;
    }
    if (instance_id.empty()) return ipc::make_error("no_vm_instance");

    // Check for stored VM analysis result
    std::string result_key = "vm_result_" + instance_id;
    auto stored = config_store_->get(result_key);
    if (!stored.is_null()) {
        return ipc::make_success(stored);
    }
    return ipc::make_success({{"status", "no_result"}});
}

json MessageHandler::handle_vm_has_snapshot(const json& payload) {
    std::string image_id = payload.value("imageId", "");
    if (image_id.empty()) return ipc::make_error("imageId_required");

    // Windows Sandbox doesn't need snapshots — always ready.
    if (WindowsSandbox::is_available() && image_id == "reactos-0.4.15") {
        return ipc::make_success({{"imageId", image_id}, {"hasSnapshot", true}});
    }

    auto snapshots = config_store_->get("vm_snapshots");
    bool has = false;
    if (snapshots.is_object() && snapshots.contains(image_id)) {
        has = true;
    }
    return ipc::make_success({{"imageId", image_id}, {"hasSnapshot", has}});
}

json MessageHandler::handle_vm_prepare_snapshot(const json& payload) {
    std::string image_id = payload.value("imageId", "");
    if (image_id.empty()) return ipc::make_error("imageId_required");

    if (event_bridge_) {
        event_bridge_->push("vm_snapshot_progress", {
            {"imageId", image_id}, {"status", "preparing"}, {"progress", 0}
        });
    }
    return ipc::make_success({{"status", "snapshot_preparing"}, {"imageId", image_id}});
}

json MessageHandler::handle_vm_get_ca_cert(const json& /*payload*/) {
    auto cert = config_store_->get("vm_ca_cert_pem");
    if (cert.is_string()) {
        return ipc::make_success({{"pem", cert.get<std::string>()}});
    }
    return ipc::make_success({{"pem", ""}});
}

json MessageHandler::handle_vm_build_agent(const json& payload) {
    std::string platform = payload.value("platform", "linux");
    if (event_bridge_) {
        event_bridge_->push("vm_status", {{"status", "building_agent"}, {"platform", platform}});
    }
    return ipc::make_success({{"status", "build_started"}, {"platform", platform}});
}

json MessageHandler::handle_vm_get_agent_status(const json& /*payload*/) {
    auto status = config_store_->get("vm_agent_status");
    if (status.is_null()) {
        return ipc::make_success({{"status", "not_built"}, {"platforms", json::object()}});
    }
    return ipc::make_success(status);
}

// ═══════════════════════════════════════════════════════
// Log Analysis Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_get_log_result(const json& payload) {
    std::string result_id = payload.value("resultId", "");
    if (result_id.empty()) return ipc::make_error("resultId_required");

    std::lock_guard<std::mutex> lock(results_mutex_);
    auto it = analysis_results_.find(result_id);
    if (it != analysis_results_.end()) {
        return ipc::make_success(it->second);
    }
    return ipc::make_error("result_not_found");
}

json MessageHandler::handle_delete_log_result(const json& payload) {
    std::string result_id = payload.value("resultId", "");
    if (result_id.empty()) return ipc::make_error("resultId_required");

    std::lock_guard<std::mutex> lock(results_mutex_);
    analysis_results_.erase(result_id);
    return ipc::make_success({{"deleted", result_id}});
}

json MessageHandler::handle_get_log_formats(const json& /*payload*/) {
    json formats = json::array();
    formats.push_back({{"id", "auto"}, {"name", "Auto-Detect"}});
    formats.push_back({{"id", "csv"}, {"name", "CSV"}});
    formats.push_back({{"id", "json"}, {"name", "JSON / NDJSON"}});
    formats.push_back({{"id", "syslog"}, {"name", "Syslog"}});
    formats.push_back({{"id", "evtx"}, {"name", "Windows EVTX"}});
    formats.push_back({{"id", "cef"}, {"name", "CEF (Common Event Format)"}});
    formats.push_back({{"id", "leef"}, {"name", "LEEF (Log Event Extended Format)"}});
    formats.push_back({{"id", "clf"}, {"name", "Common Log Format (Apache)"}});
    formats.push_back({{"id", "w3c"}, {"name", "W3C Extended Log Format"}});
    return ipc::make_success({{"formats", formats}});
}

json MessageHandler::handle_open_log_file(const json& payload) {
    if (!ui_client_) return ipc::make_error("no_ui_client");
    auto path = ui_client_->open_file_dialog("Open Log", "log,csv,json,evtx,txt,xml,syslog,cef,leef,w3c,xlsx,xls,tsv,ndjson,jsonl");
    if (path.empty()) {
        return ipc::make_success({{"cancelled", true}});
    }

    std::string session_id = payload.value("sessionId", "");

    // Extract filename
    std::string filename = path;
    auto last_sep = path.find_last_of("/\\");
    if (last_sep != std::string::npos) {
        filename = path.substr(last_sep + 1);
    }

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string result_id = "log_" + std::to_string(now_ms);

    if (event_bridge_) {
        event_bridge_->push_log_progress(result_id, filename, "analyzing");
    }

    // Read the file
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return ipc::make_error("Failed to open file: " + path);
    }
    auto size = file.tellg();
    if (size <= 0) {
        return ipc::make_error("File is empty");
    }
    file.seekg(0);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(data.data()), size);

    FileBuffer fb;
    fb.data = std::move(data);
    fb.filename = filename;
    fb.mime_type = "text/plain";

    // Step 1: Detect format and parse events
    auto format = log_manager_->detect_format(fb.ptr(), fb.size());
    std::string format_name = "unknown";
    switch (format) {
        case LogFormat::kCsv: format_name = "csv"; break;
        case LogFormat::kJson: format_name = "json"; break;
        case LogFormat::kEvtx: format_name = "evtx"; break;
        case LogFormat::kSyslog: format_name = "syslog"; break;
        case LogFormat::kCef: format_name = "cef"; break;
        case LogFormat::kLeef: format_name = "leef"; break;
        case LogFormat::kW3c: format_name = "w3c"; break;
        case LogFormat::kApache: format_name = "apache"; break;
        case LogFormat::kNginx: format_name = "nginx"; break;
        default: format_name = "auto"; break;
    }

    auto parse_result = log_manager_->parse(fb.ptr(), fb.size(), format);
    json events_json = json::array();
    json severity_counts = {{"info", 0}, {"low", 0}, {"medium", 0}, {"high", 0}, {"critical", 0}};
    json category_counts = json::object();
    int parse_errors = 0;

    std::vector<NormalizedEvent>* parsed_events = nullptr;
    if (parse_result.ok()) {
        parsed_events = &parse_result.value();

        // Normalize: extract canonical metadata (_user, _src_ip, _command etc.)
        // from structured fields AND from message text patterns
        LogNormalizer normalizer;
        normalizer.normalize(*parsed_events);

        int max_events = std::min(static_cast<int>(parsed_events->size()), 5000);
        for (int i = 0; i < max_events; ++i) {
            auto& ev = (*parsed_events)[i];
            std::string sev_str = (ev.severity == Severity::kCritical) ? "critical" :
                                  (ev.severity == Severity::kHigh) ? "high" :
                                  (ev.severity == Severity::kMedium) ? "medium" :
                                  (ev.severity == Severity::kLow) ? "low" : "info";

            // Use _raw_timestamp from fields if numeric timestamp is 0
            std::string ts_str;
            if (ev.timestamp > 0) {
                ts_str = std::to_string(ev.timestamp);
            } else if (!ev.fields.is_null() && ev.fields.contains("_raw_timestamp")) {
                ts_str = ev.fields["_raw_timestamp"].get<std::string>();
            }

            // Derive category: use event_type if set, else source, else "other"
            std::string category = ev.event_type;
            if (category.empty()) category = ev.source;
            if (category.empty()) category = "other";

            events_json.push_back({
                {"timestamp", ts_str},
                {"source", ev.source},
                {"eventType", ev.event_type},
                {"severity", sev_str},
                {"category", category},
                {"message", ev.message},
                {"raw", ev.message},
                {"metadata", ev.fields.is_null() ? json::object() : ev.fields},
            });
            severity_counts[sev_str] = severity_counts.value(sev_str, 0) + 1;
            std::string cat = ev.event_type.empty() ? "other" : ev.event_type;
            category_counts[cat] = category_counts.value(cat, 0) + 1;
        }
    } else {
        parse_errors = 1;
    }

    // Step 2: Run detector for findings
    auto analysis = log_manager_->analyze(fb);
    std::vector<Finding> findings;
    if (analysis.ok()) {
        findings = std::move(analysis.value().findings);
    }

    // Step 3: Run full analysis engine (triage, investigation, graph, verdict, hunting)
    LogAnalysisEngine::Result engine_result;
    if (parsed_events && !parsed_events->empty()) {
        engine_result = log_analysis_engine_->analyze(*parsed_events, findings);
    } else {
        // Empty results
        engine_result.insights = json::array();
        engine_result.triage = nullptr;
        engine_result.investigation = nullptr;
        engine_result.graph = nullptr;
        engine_result.verdict = nullptr;
        engine_result.hunting = nullptr;
    }

    // Build full LogAnalysisResult matching renderer's expected shape
    json log_result = {
        {"id", result_id},
        {"sessionId", session_id},
        {"fileName", filename},
        {"format", format_name},
        {"eventCount", static_cast<int>(events_json.size())},
        {"parseErrors", parse_errors},
        {"severityCounts", severity_counts},
        {"categoryCounts", category_counts},
        {"events", events_json},
        {"insights", engine_result.insights},
        {"triage", engine_result.triage},
        {"investigation", engine_result.investigation},
        {"graph", engine_result.graph},
        {"verdict", engine_result.verdict},
        {"hunting", engine_result.hunting},
        {"status", "complete"},
        {"error", analysis.ok() ? "" : analysis.error().message},
        {"startedAt", now_ms},
        {"completedAt", std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()},
    };

    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        analysis_results_[result_id] = log_result;
    }

    if (event_bridge_) {
        event_bridge_->push_log_complete(result_id, log_result);
    }

    return ipc::make_success(log_result);
}

// ═══════════════════════════════════════════════════════
// Capture Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_get_capture_status(const json& payload) {
    int browser_id = payload.value("browser_id", -1);
    if (browser_id < 0 && ui_client_ && ui_client_->content_browser()) {
        browser_id = ui_client_->content_browser()->GetIdentifier();
    }
    bool capturing = false;
    int request_count = 0;

    if (browser_id >= 0) {
        capturing = capture_manager_->is_capturing(browser_id);
        request_count = static_cast<int>(capture_manager_->get_requests(browser_id).size());
    }
    return ipc::make_success({
        {"capturing", capturing}, {"requestCount", request_count}
    });
}

json MessageHandler::handle_get_screenshots(const json& /*payload*/) {
    auto screenshots = config_store_->get("captured_screenshots");
    if (!screenshots.is_array()) screenshots = json::array();
    return ipc::make_success({{"screenshots", screenshots}});
}

json MessageHandler::handle_get_dom_snapshots(const json& /*payload*/) {
    auto snapshots = config_store_->get("captured_dom_snapshots");
    if (!snapshots.is_array()) snapshots = json::array();
    return ipc::make_success({{"snapshots", snapshots}});
}

// ═══════════════════════════════════════════════════════
// Content Analysis Handler
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_get_content_findings(const json& /*payload*/) {
    // Return content analysis findings from results cache
    std::lock_guard<std::mutex> lock(results_mutex_);
    json findings = json::array();
    for (const auto& [sha256, result] : analysis_results_) {
        if (result.contains("engine") && result["engine"] == "content") {
            if (result.contains("findings")) {
                for (const auto& f : result["findings"]) {
                    json entry = f;
                    entry["sha256"] = sha256;
                    findings.push_back(entry);
                }
            }
        }
    }
    return ipc::make_success({{"findings", findings}});
}

// ═══════════════════════════════════════════════════════
// Proxy Handler
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_test_proxy(const json& payload) {
    std::string host = payload.value("host", "");
    int port = payload.value("port", 0);
    if (host.empty() || port == 0) {
        return ipc::make_error("host_and_port_required");
    }

    // Simple TCP connection test via HttpClient
    std::string test_url = "http://" + host + ":" + std::to_string(port);
    auto result = auth_http_->get_raw("https://httpbin.org/get",
        {{"Accept", "application/json"}});

    if (result.ok()) {
        return ipc::make_success({{"reachable", true}, {"latency_ms", 0}});
    }
    return ipc::make_success({{"reachable", false}, {"error", result.error().message}});
}

// ═══════════════════════════════════════════════════════
// Report Preview Handler
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_preview_report(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) return ipc::make_error("sha256_required");

    json verdict_data;
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        auto it = analysis_results_.find(sha256);
        if (it == analysis_results_.end() || it->second.value("status", "") != "complete") {
            return ipc::make_error("analysis_not_complete");
        }
        verdict_data = it->second.value("verdict", json::object());
    }

    ThreatVerdict verdict = verdict_data.get<ThreatVerdict>();
    auto result = export_manager_->export_html(verdict, sha256);
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }
    return ipc::make_success({{"html", result.value()}});
}

// ═══════════════════════════════════════════════════════
// Save Report — Native save dialog + file write
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_save_report(const json& payload) {
    if (!ui_client_) return ipc::make_error("no_ui_client");

    std::string content = payload.value("content", "");
    std::string default_name = payload.value("defaultName", "report.html");
    std::string extension = payload.value("extension", "html");

    if (content.empty()) return ipc::make_error("empty_content");

    std::string path = ui_client_->save_file_dialog(
        "Save Report", default_name, extension);

    if (path.empty()) {
        return ipc::make_success({{"cancelled", true}});
    }

    // Write content to file
    try {
        std::ofstream out(path, std::ios::binary);
        if (!out.is_open()) {
            return ipc::make_error("cannot_open_file");
        }
        out.write(content.data(), content.size());
        out.close();

        return ipc::make_success({
            {"filePath", path},
            {"fileSize", static_cast<int64_t>(content.size())}
        });
    } catch (const std::exception& e) {
        return ipc::make_error(std::string("write_failed: ") + e.what());
    }
}

// ═══════════════════════════════════════════════════════
// Session Handlers (main-process state)
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_session_create(const json& payload) {
    std::string case_name = payload.value("caseName", "Untitled");
    std::string url = payload.value("url", "");
    json proxy_config = payload.value("proxyConfig", json(nullptr));

    auto session = session_manager_->create_session(case_name, url, proxy_config);

    // If URL provided, navigate the content browser
    if (!url.empty() && ui_client_) {
        std::string nav_url = url;
        if (nav_url.compare(0, 7, "http://") != 0 &&
            nav_url.compare(0, 8, "https://") != 0 &&
            nav_url != "about:blank") {
            nav_url = "https://" + nav_url;
        }
        ui_client_->navigate_content(nav_url);
    }

    return ipc::make_success({
        {"id", session.id},
        {"caseId", session.case_id},
        {"caseName", session.case_name},
        {"createdAt", session.created_at},
        {"url", session.url},
        {"partition", session.partition},
        {"proxyConfig", session.proxy_config},
        {"navState", {
            {"canGoBack", false},
            {"canGoForward", false},
            {"isLoading", false},
            {"url", session.url},
        }},
    });
}

json MessageHandler::handle_session_destroy(const json& payload) {
    std::string session_id = payload.value("sessionId", "");
    if (session_id.empty()) {
        return ipc::make_error("sessionId_required");
    }

    // Clear all subsystem state for this session (match V1's destroySession)
    // Clear capture data
    if (ui_client_ && ui_client_->content_browser()) {
        int browser_id = ui_client_->content_browser()->GetIdentifier();
        capture_manager_->clear(browser_id);
    }

    // Clear file analysis results associated with this session
    // (V2 uses a flat map; V1 clears per-session — keep results for now,
    //  but stop any pending analysis)

    // Clear IOC store for the session is handled in the shim (_iocStore)

    session_manager_->destroy_session(session_id);
    return ipc::make_success();
}

json MessageHandler::handle_session_list(const json& /*payload*/) {
    auto sessions = session_manager_->list_sessions();
    json arr = json::array();
    for (const auto& s : sessions) {
        arr.push_back({
            {"id", s.id},
            {"caseId", s.case_id},
            {"caseName", s.case_name},
            {"createdAt", s.created_at},
            {"url", s.url},
            {"partition", s.partition},
            {"proxyConfig", s.proxy_config},
            {"navState", {
                {"canGoBack", s.can_go_back},
                {"canGoForward", s.can_go_forward},
                {"isLoading", s.is_loading},
                {"url", s.current_url},
            }},
        });
    }
    return ipc::make_success(arr);
}

// ═══════════════════════════════════════════════════════
// Cloud Sandbox Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_cloud_sandbox_submit(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    std::string file_id = payload.value("fileId", "");
    if (sha256.empty()) sha256 = file_id;
    if (sha256.empty()) return ipc::make_error("sha256_required");

    auto file_opt = session_manager_->get_captured_download(sha256);
    if (!file_opt.has_value()) return ipc::make_error("download_not_found");

    // Load sandbox API keys from config
    auto sandbox_keys = config_store_->get("sandboxKeys");
    if (sandbox_keys.is_object()) {
        CloudSandboxConfig cfg;
        cfg.virustotal_api_key = sandbox_keys.value("virustotal", "");
        cfg.hybridanalysis_api_key = sandbox_keys.value("hybridanalysis", "");
        cfg.joesandbox_api_key = sandbox_keys.value("joesandbox", "");
        cfg.cuckoo_url = sandbox_keys.value("cuckoo_url", "");
        cfg.cuckoo_token = sandbox_keys.value("cuckoo", "");
        cloud_sandbox_->set_config(cfg);
    }

    auto results = cloud_sandbox_->submit(file_opt.value());

    json results_json = json::array();
    for (const auto& r : results) {
        results_json.push_back({
            {"provider", r.provider},
            {"status", r.status},
            {"submissionId", r.submission_id},
            {"reportUrl", r.report_url},
            {"verdict", r.verdict},
            {"score", r.score},
            {"details", r.details},
            {"timestamp", r.timestamp},
            {"error", r.error},
        });
    }
    return ipc::make_success({{"sha256", sha256}, {"results", results_json}});
}

json MessageHandler::handle_cloud_sandbox_poll(const json& payload) {
    std::string provider = payload.value("provider", "");
    std::string submission_id = payload.value("submissionId", "");
    std::string sha256 = payload.value("sha256", "");

    if (provider.empty() || submission_id.empty()) {
        return ipc::make_error("provider_and_submissionId_required");
    }

    auto r = cloud_sandbox_->poll(provider, submission_id, sha256);
    return ipc::make_success({
        {"provider", r.provider},
        {"status", r.status},
        {"submissionId", r.submission_id},
        {"reportUrl", r.report_url},
        {"verdict", r.verdict},
        {"score", r.score},
        {"details", r.details},
        {"timestamp", r.timestamp},
        {"error", r.error},
    });
}

// ═══════════════════════════════════════════════════════
// Enrichment Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_enrichment_query(const json& payload) {
    std::string ioc = payload.value("ioc", "");
    std::string ioc_type = payload.value("iocType", "");
    std::string session_id = payload.value("sessionId", "");

    if (ioc.empty()) {
        return ipc::make_error("ioc_required");
    }

    // Load API keys from config into enrichment manager
    auto api_keys = config_store_->get("apiKeys");
    if (api_keys.is_object()) {
        EnrichmentConfig cfg;
        cfg.virustotal_api_key = api_keys.value("virustotal", "");
        cfg.abuseipdb_api_key = api_keys.value("abuseipdb", "");
        cfg.otx_api_key = api_keys.value("otx", "");
        enrichment_manager_->set_config(cfg);
    }

    json results = json::array();

    // Route to appropriate providers based on IOC type
    if (ioc_type == "hash") {
        // Query hash-based providers: VirusTotal, OTX, URLhaus
        auto vt = enrichment_manager_->query_virustotal(ioc);
        if (vt.ok()) {
            auto& pr = vt.value();
            results.push_back({
                {"provider", pr.provider_name},
                {"ioc", ioc},
                {"iocType", ioc_type},
                {"verdict", pr.reputation},
                {"confidence", pr.found ? (pr.detection_count * 100 / std::max(pr.total_engines, 1)) : 0},
                {"summary", pr.provider_name + ": " + std::to_string(pr.detection_count) + "/" + std::to_string(pr.total_engines) + " detections"},
                {"details", {{"found", pr.found}, {"detection_count", pr.detection_count}, {"total_engines", pr.total_engines}}},
                {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
            });
        }
        auto otx = enrichment_manager_->query_otx(ioc);
        if (otx.ok()) {
            auto& pr = otx.value();
            results.push_back({
                {"provider", pr.provider_name},
                {"ioc", ioc},
                {"iocType", ioc_type},
                {"verdict", pr.reputation},
                {"confidence", pr.found ? 70 : 0},
                {"summary", pr.provider_name + ": " + std::to_string(pr.detection_count) + " pulse(s)"},
                {"details", {{"found", pr.found}, {"pulse_count", pr.detection_count}}},
                {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
            });
        }
        auto uh = enrichment_manager_->query_urlhaus(ioc);
        if (uh.ok()) {
            auto& pr = uh.value();
            results.push_back({
                {"provider", pr.provider_name},
                {"ioc", ioc},
                {"iocType", ioc_type},
                {"verdict", pr.reputation},
                {"confidence", pr.found ? 90 : 0},
                {"summary", pr.found ? "Known malware payload" : "Not found in URLhaus"},
                {"details", {{"found", pr.found}}},
                {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
            });
        }
    } else if (ioc_type == "ip") {
        // Query IP-based providers: AbuseIPDB, OTX, VirusTotal
        auto abuse = enrichment_manager_->query_abuseipdb(ioc);
        if (abuse.ok()) {
            auto& pr = abuse.value();
            results.push_back({
                {"provider", pr.provider_name},
                {"ioc", ioc},
                {"iocType", ioc_type},
                {"verdict", pr.reputation},
                {"confidence", pr.detection_count},
                {"summary", pr.provider_name + ": abuse confidence " + std::to_string(pr.detection_count) + "%"},
                {"details", {{"found", pr.found}, {"confidence_score", pr.detection_count}}},
                {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
            });
        }
        auto vt = enrichment_manager_->query_virustotal(ioc);
        if (vt.ok()) {
            auto& pr = vt.value();
            results.push_back({
                {"provider", pr.provider_name},
                {"ioc", ioc},
                {"iocType", ioc_type},
                {"verdict", pr.reputation},
                {"confidence", pr.found ? (pr.detection_count * 100 / std::max(pr.total_engines, 1)) : 0},
                {"summary", pr.provider_name + ": " + std::to_string(pr.detection_count) + "/" + std::to_string(pr.total_engines) + " detections"},
                {"details", {{"found", pr.found}, {"detection_count", pr.detection_count}, {"total_engines", pr.total_engines}}},
                {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
            });
        }
    } else if (ioc_type == "domain" || ioc_type == "url") {
        // Query domain/URL-based providers: VirusTotal, URLhaus
        auto vt = enrichment_manager_->query_virustotal(ioc);
        if (vt.ok()) {
            auto& pr = vt.value();
            results.push_back({
                {"provider", pr.provider_name},
                {"ioc", ioc},
                {"iocType", ioc_type},
                {"verdict", pr.reputation},
                {"confidence", pr.found ? (pr.detection_count * 100 / std::max(pr.total_engines, 1)) : 0},
                {"summary", pr.provider_name + ": " + std::to_string(pr.detection_count) + "/" + std::to_string(pr.total_engines) + " detections"},
                {"details", {{"found", pr.found}, {"detection_count", pr.detection_count}, {"total_engines", pr.total_engines}}},
                {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
            });
        }
        auto uh = enrichment_manager_->query_urlhaus(ioc);
        if (uh.ok()) {
            auto& pr = uh.value();
            results.push_back({
                {"provider", pr.provider_name},
                {"ioc", ioc},
                {"iocType", ioc_type},
                {"verdict", pr.reputation},
                {"confidence", pr.found ? 90 : 0},
                {"summary", pr.found ? "Known malware payload" : "Not found in URLhaus"},
                {"details", {{"found", pr.found}}},
                {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
            });
        }
    }

    if (results.empty()) {
        return ipc::make_success({
            {"ioc", ioc},
            {"iocType", ioc_type},
            {"status", "no_providers"},
            {"results", json::array()},
            {"message", "No API keys configured. Add API keys in Settings > Integrations to enable enrichment."},
        });
    }

    // Determine aggregate verdict
    std::string best_verdict = "clean";
    for (const auto& r : results) {
        std::string v = r.value("verdict", "unknown");
        if (v == "malicious") { best_verdict = "malicious"; break; }
        if (v == "suspicious" && best_verdict != "malicious") best_verdict = "suspicious";
        if (v == "low_risk" && best_verdict == "clean") best_verdict = "low_risk";
    }

    json response = {
        {"ioc", ioc},
        {"iocType", ioc_type},
        {"status", "done"},
        {"verdict", best_verdict},
        {"results", results},
    };

    // Phase 3b: Emit enrichment_result event for real-time renderer updates
    if (event_bridge_ && !session_id.empty()) {
        json event_data = response;
        event_data["sessionId"] = session_id;
        event_data["value"] = ioc;
        event_data["type"] = ioc_type;
        event_data["source"] = "manual";
        event_data["firstSeen"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        event_data["safe"] = false;
        event_data["domain"] = (ioc_type == "domain") ? ioc : "";
        event_bridge_->push("enrichment_result", event_data);
    }

    return ipc::make_success(response);
}

json MessageHandler::handle_enrichment_get_results(const json& payload) {
    std::string session_id = payload.value("sessionId", "");
    // Return enrichment results from analysis cache
    std::lock_guard<std::mutex> lock(results_mutex_);
    json enrichment_results = json::array();
    for (const auto& [sha256, result] : analysis_results_) {
        if (result.contains("verdict") && result["verdict"].is_object()) {
            auto& verdict = result["verdict"];
            if (verdict.contains("findings")) {
                for (const auto& f : verdict["findings"]) {
                    if (f.value("engine", "") == "enrichment") {
                        json entry = f;
                        entry["sha256"] = sha256;
                        entry["sessionId"] = session_id;
                        enrichment_results.push_back(entry);
                    }
                }
            }
        }
    }
    return ipc::make_success(enrichment_results);
}

// ═══════════════════════════════════════════════════════
// URL Chain Investigation
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_investigate_url(const json& payload) {
    std::string url = payload.value("url", "");
    std::string session_id = payload.value("sessionId", "");
    if (url.empty()) return ipc::make_error("url_required");

    // Auto-prepend https:// if needed
    if (url.compare(0, 7, "http://") != 0 &&
        url.compare(0, 8, "https://") != 0) {
        url = "https://" + url;
    }

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string chain_id = "chain_" + std::to_string(now_ms);

    // Emit "investigating" event immediately
    if (event_bridge_) {
        event_bridge_->push("url_chain_update", {
            {"chainId", chain_id}, {"status", "investigating"},
            {"sessionId", session_id}, {"originalUrl", url},
            {"hops", json::array()},
        });
    }

    // Follow the redirect chain using a dedicated HTTP client (no redirect following)
    auto* bridge = event_bridge_;
    auto* tfm = threat_feed_manager_.get();
    auto* ca = content_analyzer_.get();
    auto* chains = &url_chains_;
    auto* mtx = &results_mutex_;

    std::jthread thread([chain_id, url, session_id, bridge, tfm, ca,
                         chains, mtx](std::stop_token stop) {
        // Create a dedicated HTTP client that doesn't follow redirects
        HttpClient http;
        http.set_timeout(10);
        http.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        constexpr int kMaxHops = 20;
        json hops = json::array();
        std::string current_url = url;
        std::string final_url;
        std::vector<std::string> all_domains;
        json threat_matches = json::array();
        json content_findings = json::array();
        bool chain_is_malicious = false;

        for (int hop = 0; hop < kMaxHops && !stop.stop_requested(); ++hop) {
            auto hop_start = std::chrono::steady_clock::now();

            // Extract domain for this hop
            std::string host;
            auto scheme_end = current_url.find("://");
            if (scheme_end != std::string::npos) {
                auto host_start = scheme_end + 3;
                auto host_end = current_url.find_first_of(":/?#", host_start);
                host = (host_end == std::string::npos)
                    ? current_url.substr(host_start)
                    : current_url.substr(host_start, host_end - host_start);
            }
            if (!host.empty()) all_domains.push_back(host);

            // Check against threat feeds
            bool is_threat = false;
            if (tfm) {
                if (tfm->is_known_threat("domain", host) ||
                    tfm->is_known_threat("url", current_url)) {
                    is_threat = true;
                    chain_is_malicious = true;
                    threat_matches.push_back({
                        {"hop", hop}, {"url", current_url}, {"domain", host},
                        {"matchType", "threat_feed"},
                    });
                }
            }

            // Make HTTP request (don't follow redirects automatically)
            std::unordered_map<std::string, std::string> headers = {
                {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                {"Accept", "text/html,application/xhtml+xml,*/*"},
            };

            int status_code = 0;
            std::string redirect_to;
            std::string content_type;
            std::string response_body;
            std::string server_ip;
            double duration_ms = 0;

            auto result = http.get_no_follow(current_url, headers);
            auto hop_end = std::chrono::steady_clock::now();
            duration_ms = std::chrono::duration<double, std::milli>(hop_end - hop_start).count();

            if (result.ok()) {
                auto& resp = result.value();
                status_code = resp.status_code;
                response_body = resp.body;

                // Extract headers
                for (const auto& [k, v] : resp.headers) {
                    std::string key_lower = k;
                    for (auto& c : key_lower)
                        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (key_lower == "location") redirect_to = v;
                    else if (key_lower == "content-type") content_type = v;
                }
            } else {
                // Connection failed
                json hop_entry = {
                    {"hop", hop}, {"url", current_url}, {"domain", host},
                    {"statusCode", 0}, {"error", result.error().message},
                    {"duration_ms", duration_ms}, {"isThreat", is_threat},
                };
                hops.push_back(hop_entry);
                break;
            }

            // Run content analysis on response body (detect phishing pages)
            if (ca && !response_body.empty() &&
                content_type.find("text/html") != std::string::npos) {
                FileBuffer content_fb;
                content_fb.data.assign(response_body.begin(), response_body.end());
                content_fb.filename = current_url;
                content_fb.mime_type = content_type;
                auto ca_result = ca->analyze(content_fb);
                if (ca_result.ok() && !ca_result.value().findings.empty()) {
                    for (const auto& f : ca_result.value().findings) {
                        content_findings.push_back({
                            {"hop", hop}, {"url", current_url},
                            {"title", f.title}, {"description", f.description},
                            {"severity", f.severity},
                        });
                        if (f.severity == Severity::kHigh || f.severity == Severity::kCritical) {
                            chain_is_malicious = true;
                        }
                    }
                }
            }

            // Check for meta refresh redirects in HTML
            if (redirect_to.empty() && !response_body.empty() &&
                content_type.find("text/html") != std::string::npos) {
                // Look for <meta http-equiv="refresh" content="0;url=...">
                std::string body_lower = response_body;
                for (auto& c : body_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                auto meta_pos = body_lower.find("http-equiv=\"refresh\"");
                if (meta_pos == std::string::npos) meta_pos = body_lower.find("http-equiv='refresh'");
                if (meta_pos != std::string::npos) {
                    auto url_pos = body_lower.find("url=", meta_pos);
                    if (url_pos != std::string::npos) {
                        url_pos += 4;
                        auto end_pos = body_lower.find_first_of("\"' >", url_pos);
                        if (end_pos != std::string::npos) {
                            redirect_to = response_body.substr(url_pos, end_pos - url_pos);
                        }
                    }
                }
                // Also check window.location / document.location redirects
                for (const auto& pattern : {"window.location", "document.location", "location.href"}) {
                    auto loc_pos = body_lower.find(pattern);
                    if (loc_pos != std::string::npos) {
                        // Find the URL in quotes after the assignment
                        auto eq_pos = body_lower.find_first_of("='\"", loc_pos + strlen(pattern));
                        if (eq_pos != std::string::npos) {
                            auto quote = body_lower[eq_pos];
                            if (quote == '=') {
                                eq_pos = body_lower.find_first_of("'\"", eq_pos + 1);
                                if (eq_pos == std::string::npos) break;
                                quote = body_lower[eq_pos];
                            }
                            auto url_start = eq_pos + 1;
                            auto url_end = body_lower.find(quote, url_start);
                            if (url_end != std::string::npos && redirect_to.empty()) {
                                redirect_to = response_body.substr(url_start, url_end - url_start);
                            }
                        }
                        break;
                    }
                }
            }

            json hop_entry = {
                {"hop", hop}, {"url", current_url}, {"domain", host},
                {"statusCode", status_code}, {"contentType", content_type},
                {"redirectTo", redirect_to}, {"duration_ms", duration_ms},
                {"isThreat", is_threat},
                {"bodySize", response_body.size()},
            };
            hops.push_back(hop_entry);

            // Emit progress event
            if (bridge) {
                bridge->push("url_chain_update", {
                    {"chainId", chain_id}, {"status", "investigating"},
                    {"sessionId", session_id}, {"originalUrl", url},
                    {"currentHop", hop}, {"currentUrl", current_url},
                    {"hops", hops},
                });
            }

            // Follow redirect if present
            if (!redirect_to.empty() && status_code >= 300 && status_code < 400) {
                // Handle relative redirects
                if (redirect_to.compare(0, 4, "http") != 0) {
                    if (redirect_to[0] == '/') {
                        auto origin_end = current_url.find('/', scheme_end + 3);
                        redirect_to = current_url.substr(0, origin_end) + redirect_to;
                    } else {
                        auto last_slash = current_url.rfind('/');
                        redirect_to = current_url.substr(0, last_slash + 1) + redirect_to;
                    }
                }
                current_url = redirect_to;
                continue;
            }

            // Follow meta/JS redirect if not an HTTP redirect
            if (!redirect_to.empty() && (status_code == 200 || status_code == 0)) {
                if (redirect_to.compare(0, 4, "http") != 0) {
                    if (redirect_to[0] == '/') {
                        auto origin_end = current_url.find('/', scheme_end + 3);
                        redirect_to = current_url.substr(0, origin_end) + redirect_to;
                    }
                }
                current_url = redirect_to;
                continue;
            }

            // No more redirects — this is the final URL
            final_url = current_url;
            break;
        }

        if (final_url.empty()) final_url = current_url;

        // Determine overall verdict
        std::string verdict = "clean";
        int risk_score = 0;
        if (chain_is_malicious) {
            verdict = "malicious";
            risk_score = 90;
        } else if (!threat_matches.empty()) {
            verdict = "suspicious";
            risk_score = 60;
        } else if (!content_findings.empty()) {
            verdict = "suspicious";
            risk_score = 50;
        } else if (hops.size() > 3) {
            verdict = "suspicious";
            risk_score = 30;
        }

        // Build final result
        json chain_result = {
            {"chainId", chain_id},
            {"sessionId", session_id},
            {"status", "complete"},
            {"originalUrl", url},
            {"finalUrl", final_url},
            {"hopCount", hops.size()},
            {"hops", hops},
            {"domains", all_domains},
            {"threatMatches", threat_matches},
            {"contentFindings", content_findings},
            {"verdict", verdict},
            {"riskScore", risk_score},
            {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()},
        };

        // Store result
        {
            std::lock_guard<std::mutex> lock(*mtx);
            (*chains)[chain_id] = chain_result;
        }

        // Emit completion event
        if (bridge) {
            bridge->push("url_chain_update", chain_result);

            // Register all domains as IOCs
            for (const auto& domain : all_domains) {
                bridge->push("enrichment_result", {
                    {"value", domain}, {"type", "domain"},
                    {"source", "url_chain"}, {"status", "pending"},
                    {"safe", false}, {"domain", domain},
                    {"firstSeen", std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count()},
                    {"results", json::array()},
                });
            }
        }
    });

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        analysis_threads_.push_back(std::move(thread));
    }

    return ipc::make_success({
        {"chainId", chain_id},
        {"status", "investigating"},
        {"originalUrl", url},
    });
}

json MessageHandler::handle_get_url_chains(const json& /*payload*/) {
    std::lock_guard<std::mutex> lock(results_mutex_);
    json arr = json::array();
    for (const auto& [id, chain] : url_chains_) {
        arr.push_back(chain);
    }
    return ipc::make_success(arr);
}

// ═══════════════════════════════════════════════════════
// Document Preview
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_get_file_preview(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    std::string file_id = payload.value("fileId", "");
    if (sha256.empty()) sha256 = file_id;
    if (sha256.empty()) return ipc::make_error("sha256_required");

    auto file_opt = session_manager_->get_captured_download(sha256);
    if (!file_opt.has_value()) return ipc::make_error("file_not_found");

    auto& file = file_opt.value();
    std::string mime = file.mime_type;
    std::string filename = file.filename;

    // Determine if this file type is previewable
    // Lowercase the filename for extension checks
    std::string fn_lower = filename;
    for (auto& c : fn_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Non-previewable types — skip binary/archive/executable formats
    static const std::vector<std::string> skip_exts = {
        ".exe", ".dll", ".sys", ".drv", ".ocx", ".com", ".scr",
        ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst",
        ".iso", ".img", ".dmg", ".vmdk", ".vhd", ".qcow2",
        ".bin", ".dat", ".dmp", ".msi", ".cab", ".wim",
    };
    for (const auto& ext : skip_exts) {
        if (fn_lower.size() >= ext.size() &&
            fn_lower.compare(fn_lower.size() - ext.size(), ext.size(), ext) == 0) {
            return ipc::make_success({
                {"previewable", false},
                {"reason", "Binary/archive file type not previewable"},
                {"fileType", ext},
            });
        }
    }

    // Determine MIME type for embedding
    std::string preview_mime = mime;
    if (preview_mime.empty() || preview_mime == "application/octet-stream") {
        // Detect from extension
        if (fn_lower.ends_with(".pdf")) preview_mime = "application/pdf";
        else if (fn_lower.ends_with(".png")) preview_mime = "image/png";
        else if (fn_lower.ends_with(".jpg") || fn_lower.ends_with(".jpeg")) preview_mime = "image/jpeg";
        else if (fn_lower.ends_with(".gif")) preview_mime = "image/gif";
        else if (fn_lower.ends_with(".bmp")) preview_mime = "image/bmp";
        else if (fn_lower.ends_with(".svg")) preview_mime = "image/svg+xml";
        else if (fn_lower.ends_with(".webp")) preview_mime = "image/webp";
        else if (fn_lower.ends_with(".tiff") || fn_lower.ends_with(".tif")) preview_mime = "image/tiff";
        else if (fn_lower.ends_with(".htm") || fn_lower.ends_with(".html")) preview_mime = "text/html";
        else if (fn_lower.ends_with(".txt") || fn_lower.ends_with(".log") || fn_lower.ends_with(".csv")) preview_mime = "text/plain";
        else if (fn_lower.ends_with(".xml")) preview_mime = "text/xml";
        else if (fn_lower.ends_with(".json")) preview_mime = "application/json";
        else if (fn_lower.ends_with(".rtf")) preview_mime = "application/rtf";
        else if (fn_lower.ends_with(".docx")) preview_mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
        else if (fn_lower.ends_with(".xlsx")) preview_mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
        else if (fn_lower.ends_with(".pptx")) preview_mime = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
        else if (fn_lower.ends_with(".doc")) preview_mime = "application/msword";
        else if (fn_lower.ends_with(".xls")) preview_mime = "application/vnd.ms-excel";
        else if (fn_lower.ends_with(".ppt")) preview_mime = "application/vnd.ms-powerpoint";
        else if (fn_lower.ends_with(".eml") || fn_lower.ends_with(".msg")) preview_mime = "message/rfc822";
    }

    // Determine preview category
    std::string category = "unsupported";
    if (preview_mime.find("pdf") != std::string::npos) category = "pdf";
    else if (preview_mime.find("image/") != std::string::npos) category = "image";
    else if (preview_mime.find("text/") != std::string::npos ||
             preview_mime.find("json") != std::string::npos ||
             preview_mime.find("xml") != std::string::npos) category = "text";
    else if (preview_mime.find("officedocument") != std::string::npos ||
             preview_mime.find("msword") != std::string::npos ||
             preview_mime.find("ms-excel") != std::string::npos ||
             preview_mime.find("ms-powerpoint") != std::string::npos ||
             preview_mime.find("rtf") != std::string::npos) category = "office";

    // Encode file data as base64
    static constexpr char b64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    auto encode_b64 = [&](const uint8_t* data, size_t len) -> std::string {
        std::string out;
        out.reserve(((len + 2) / 3) * 4);
        for (size_t i = 0; i < len; i += 3) {
            uint32_t n = static_cast<uint32_t>(data[i]) << 16;
            if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
            if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
            out.push_back(b64_table[(n >> 18) & 0x3F]);
            out.push_back(b64_table[(n >> 12) & 0x3F]);
            out.push_back((i + 1 < len) ? b64_table[(n >> 6) & 0x3F] : '=');
            out.push_back((i + 2 < len) ? b64_table[n & 0x3F] : '=');
        }
        return out;
    };

    // Limit preview data: for text, cap at 50KB; for binary, cap at 10MB
    size_t max_size = (category == "text") ? 50 * 1024 : 10 * 1024 * 1024;
    size_t preview_size = std::min(file.size(), max_size);

    std::string b64_data = encode_b64(file.ptr(), preview_size);
    std::string data_url = "data:" + preview_mime + ";base64," + b64_data;

    // For text files, also include raw text for code viewer
    std::string text_content;
    if (category == "text" && file.size() <= 100 * 1024) {
        text_content = std::string(reinterpret_cast<const char*>(file.ptr()),
                                    std::min(file.size(), size_t(100 * 1024)));
    }

    // For Office docs, try to extract thumbnail from ZIP structure
    // OOXML files (docx/xlsx/pptx) are ZIP archives with docProps/thumbnail.*
    std::string thumbnail_b64;
    if (category == "office" && file.size() > 30 &&
        file.data[0] == 'P' && file.data[1] == 'K') {
        // Simple ZIP scan for thumbnail — look for "docProps/thumbnail" filename
        std::string zip_str(reinterpret_cast<const char*>(file.ptr()), file.size());
        auto thumb_pos = zip_str.find("docProps/thumbnail");
        if (thumb_pos != std::string::npos) {
            // Found reference, but extracting from ZIP properly requires libarchive
            // For now, mark that thumbnail exists
            category = "office-with-thumb";
        }
    }

    return ipc::make_success({
        {"previewable", true},
        {"sha256", sha256},
        {"filename", filename},
        {"mimeType", preview_mime},
        {"category", category},
        {"fileSize", static_cast<int64_t>(file.size())},
        {"dataUrl", data_url},
        {"textContent", text_content},
    });
}

// ═══════════════════════════════════════════════════════
// App Info / Update / Feedback Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_get_app_info(const json& /*payload*/) {
    return ipc::make_success({
        {"version", "2.0.0"},
        {"buildDate", __DATE__},
        {"platform",
#if defined(OS_MAC) || defined(OS_MACOS)
            "macOS"
#elif defined(OS_WINDOWS) || defined(_WIN32)
            "Windows"
#elif defined(OS_LINUX)
            "Linux"
#else
            "Unknown"
#endif
        },
        {"arch",
#if defined(__aarch64__) || defined(_M_ARM64)
            "arm64"
#else
            "x64"
#endif
        },
        {"engine", "CEF (Chromium Embedded Framework)"},
        {"copyright", "ShieldTier. All rights reserved."},
        {"website", "https://socbrowser.com"},
        {"support", "support@socbrowser.com"},
        {"github", "https://github.com/dillida/shieldtier-v2-browser"},
    });
}

json MessageHandler::handle_check_update(const json& /*payload*/) {
    // Check for updates from the API server
    // GET https://api.socbrowser.com/v1/update/check?version=2.0.0&platform=<platform>&arch=<arch>
    std::string platform =
#if defined(OS_MAC) || defined(OS_MACOS)
        "macos";
#elif defined(OS_WINDOWS) || defined(_WIN32)
        "windows";
#elif defined(OS_LINUX)
        "linux";
#else
        "unknown";
#endif

    std::string arch =
#if defined(__aarch64__) || defined(_M_ARM64)
        "arm64";
#else
        "x64";
#endif

    std::string url = std::string(kAuthApiUrl) +
        "/v1/update/check?version=2.0.0&platform=" + platform + "&arch=" + arch;

    try {
        auto result = auth_http_->get_raw(url);
        if (result.ok()) {
            auto& resp = result.value();
            if (resp.status_code == 200 && !resp.body.empty()) {
                auto data = json::parse(resp.body);
                bool update_available = data.value("updateAvailable", false);
                return ipc::make_success({
                    {"status", update_available ? "available" : "not-available"},
                    {"currentVersion", "2.0.0"},
                    {"availableVersion", data.value("latestVersion", "")},
                    {"downloadUrl", data.value("downloadUrl", "")},
                    {"releaseNotes", data.value("releaseNotes", "")},
                    {"downloadProgress", 0},
                    {"error", nullptr},
                });
            }
        }
    } catch (...) {}

    // Offline or server unreachable — return current state
    return ipc::make_success({
        {"status", "not-available"},
        {"currentVersion", "2.0.0"},
        {"availableVersion", nullptr},
        {"downloadProgress", 0},
        {"error", nullptr},
    });
}

json MessageHandler::handle_submit_feedback(const json& payload) {
    std::string type = payload.value("type", "general");       // bug, feature, general
    std::string message = payload.value("message", "");
    std::string email = payload.value("email", "");
    int rating = payload.value("rating", 0);                   // 1-5 stars

    if (message.empty()) {
        return ipc::make_error("Feedback message cannot be empty");
    }

    // POST https://api.socbrowser.com/v1/feedback
    std::string platform =
#if defined(OS_MAC) || defined(OS_MACOS)
        "macos";
#elif defined(OS_WINDOWS) || defined(_WIN32)
        "windows";
#elif defined(OS_LINUX)
        "linux";
#else
        "unknown";
#endif

    json body = {
        {"type", type},
        {"message", message},
        {"email", email},
        {"rating", rating},
        {"version", "2.0.0"},
        {"platform", platform},
    };

    // Include user info if logged in
    {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        if (!auth_user_.is_null() && auth_user_.contains("email")) {
            body["userEmail"] = auth_user_["email"];
        }
        if (!auth_user_.is_null() && auth_user_.contains("name")) {
            body["userName"] = auth_user_["name"];
        }
    }

    std::string url = std::string(kAuthApiUrl) + "/v1/feedback";
    try {
        auto result = auth_http_->post_raw(url, body.dump(),
            {{"Content-Type", "application/json"}});
        if (result.ok()) {
            auto& resp = result.value();
            if (resp.status_code >= 200 && resp.status_code < 300) {
                return ipc::make_success({{"submitted", true}});
            }
            return ipc::make_error("Server returned " + std::to_string(resp.status_code));
        }
        return ipc::make_error("Request failed: " + result.error().message);
    } catch (const std::exception& e) {
        return ipc::make_error("Failed to submit feedback: " + std::string(e.what()));
    }
}

}  // namespace shieldtier
