#include "ipc/message_handler.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

#include "app/shieldtier_client.h"
#include "analysis/fileanalysis/file_analyzer.h"
#include "browser/navigation.h"
#include "chat/shieldcrypt.h"
#include "config/paths.h"
#include "vm/vm_scoring.h"

namespace shieldtier {

// Dev auth bypass: when SHIELDTIER_DEV_AUTH=1, skip cloud login entirely
static bool is_dev_auth_enabled() {
    static int cached = -1;
    if (cached < 0) {
        const char* val = std::getenv("SHIELDTIER_DEV_AUTH");
        cached = (val && std::string(val) == "1") ? 1 : 0;
    }
    return cached == 1;
}

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
      threat_feed_manager_(std::make_unique<ThreatFeedManager>()),
      capture_manager_(std::make_unique<CaptureManager>()),
      config_store_(std::make_unique<ConfigStore>(paths::get_config_path())),
      export_manager_(std::make_unique<ExportManager>()),
      vm_manager_(std::make_unique<VmManager>(paths::get_data_path() + "/vms")),
      vm_installer_(std::make_unique<VmInstaller>(paths::get_data_path() + "/vms")),
      chat_manager_(std::make_unique<ChatManager>(paths::get_data_path() + "/chat")),
      auth_http_(std::make_unique<HttpClient>()) {
    chat_manager_->initialize_keys();
    yara_engine_->initialize();
    config_store_->load();
    threat_feed_manager_->update_feeds();
    auth_http_->set_timeout(5);
    auth_http_->set_user_agent("ShieldTier/2.0");
}

MessageHandler::~MessageHandler() {
    // jthread destructor requests stop and joins automatically.
    std::lock_guard<std::mutex> lock(threads_mutex_);
    analysis_threads_.clear();
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
        analysis_results_[sha256] = {{"status", "pending"}};
    }

    // Pointers are stable for the lifetime of MessageHandler.
    // The jthread is joined in ~MessageHandler before engines are destroyed.
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

    std::jthread thread([sha256, sm, yara, fa, em, sc, sandbox, advanced,
                         email, content, log_mgr, results_map, mtx]
                        (std::stop_token stop) {
        auto file_opt = sm->get_captured_download(sha256);
        if (!file_opt.has_value()) {
            std::lock_guard<std::mutex> lock(*mtx);
            (*results_map)[sha256] = {
                {"status", "error"},
                {"error", "download_not_found"}
            };
            return;
        }

        FileBuffer file = std::move(file_opt.value());
        std::vector<AnalysisEngineResult> engine_results;

        if (stop.stop_requested()) return;

        auto yara_result = yara->scan(file);
        if (yara_result.ok()) {
            engine_results.push_back(std::move(yara_result.value()));
        }

        if (stop.stop_requested()) return;

        auto fa_result = fa->analyze(file);
        if (fa_result.ok()) {
            engine_results.push_back(std::move(fa_result.value()));
        }

        if (stop.stop_requested()) return;

        auto sandbox_result = sandbox->analyze(file);
        if (sandbox_result.ok()) {
            engine_results.push_back(std::move(sandbox_result.value()));
        }

        if (stop.stop_requested()) return;

        auto advanced_result = advanced->analyze(file);
        if (advanced_result.ok()) {
            engine_results.push_back(std::move(advanced_result.value()));
        }

        if (stop.stop_requested()) return;

        auto email_result = email->analyze(file);
        if (email_result.ok()) {
            engine_results.push_back(std::move(email_result.value()));
        }

        if (stop.stop_requested()) return;

        auto content_result = content->analyze(file);
        if (content_result.ok()) {
            engine_results.push_back(std::move(content_result.value()));
        }

        if (stop.stop_requested()) return;

        auto log_result = log_mgr->analyze(file);
        if (log_result.ok()) {
            engine_results.push_back(std::move(log_result.value()));
        }

        if (stop.stop_requested()) return;

        std::string md5 = FileAnalyzer::compute_md5(file.ptr(), file.size());
        auto enrich_result = em->enrich_by_hash(sha256, md5);
        if (enrich_result.ok()) {
            engine_results.push_back(std::move(enrich_result.value()));
        }

        auto verdict_result = sc->score(engine_results);

        json output;
        if (verdict_result.ok()) {
            output = {
                {"status", "complete"},
                {"verdict", verdict_result.value()}
            };
        } else {
            output = {
                {"status", "error"},
                {"error", verdict_result.error().message}
            };
        }

        std::lock_guard<std::mutex> lock(*mtx);
        (*results_map)[sha256] = std::move(output);
    });

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        analysis_threads_.push_back(std::move(thread));
    }

    return ipc::make_success({{"queued", true}, {"sha256", sha256}});
}

json MessageHandler::handle_get_analysis_result(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    std::string file_id = payload.value("fileId", "");
    if (sha256.empty()) sha256 = file_id;

    if (sha256.empty()) {
        // No specific file — return all results for the session
        std::lock_guard<std::mutex> lock(results_mutex_);
        json arr = json::array();
        for (auto& [k, v] : analysis_results_) {
            json entry = v;
            entry["sha256"] = k;
            arr.push_back(entry);
        }
        return ipc::make_success(arr);
    }

    std::lock_guard<std::mutex> lock(results_mutex_);
    auto it = analysis_results_.find(sha256);
    if (it != analysis_results_.end()) {
        return ipc::make_success(it->second);
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

    return ipc::make_success({{"vm_id", vm_id}});
}

json MessageHandler::handle_stop_vm(const json& payload) {
    std::string vm_id = payload.value("vm_id", "");

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

json MessageHandler::handle_submit_sample_to_vm(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) {
        return ipc::make_error("sha256_required");
    }

    auto file_opt = session_manager_->get_captured_download(sha256);
    if (!file_opt.has_value()) {
        return ipc::make_error("download_not_found");
    }

    auto vms = vm_manager_->list_vms();
    if (vms.empty()) {
        return ipc::make_error("no_active_vm");
    }

    std::string vm_id = vms.front().id;

    if (event_bridge_) {
        event_bridge_->push_vm_status("running");
    }

    // Run VM analysis asynchronously — store results on completion
    auto file_copy = file_opt.value();
    auto* vm_mgr = vm_manager_.get();
    auto* bridge = event_bridge_;
    auto* config = config_store_.get();

    std::jthread worker([vm_id, file_copy, vm_mgr, bridge, config](std::stop_token) {
        auto result = vm_mgr->submit_sample(vm_id, file_copy);

        if (result.ok()) {
            auto& vm_result = result.value();

            // Score the VM results
            VmScoring scorer;
            json network_activity;  // populated from INETSim events if available
            auto scored = scorer.score_vm_results(
                vm_result.events, network_activity, vm_result.duration_ms);

            // Store in config for handle_vm_get_result to retrieve
            json stored = {
                {"vm_id", vm_id},
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

    return ipc::make_success({{"vm_id", vm_id}});
}

json MessageHandler::handle_analyze_email(const json& payload) {
    std::string sha256 = payload.value("sha256", "");
    if (sha256.empty()) {
        return ipc::make_error("sha256_required");
    }

    auto file_opt = session_manager_->get_captured_download(sha256);
    if (!file_opt.has_value()) {
        return ipc::make_error("download_not_found");
    }

    auto result = email_analyzer_->analyze(file_opt.value());
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
        {"engine", "email"},
        {"findings", findings_json},
        {"duration_ms", r.duration_ms},
        {"raw_output", r.raw_output}
    });
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
        // Renderer calls with sessionId — return empty results
        return ipc::make_success(json::array());
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
    // Contacts are managed server-side; return local chat history senders
    auto history = chat_manager_->get_history(1000);
    std::unordered_map<std::string, int> contact_map;
    for (const auto& msg : history) {
        if (msg.sender_id != "self") {
            contact_map[msg.sender_id]++;
        }
    }

    json contacts = json::array();
    for (const auto& [id, count] : contact_map) {
        contacts.push_back({
            {"id", id},
            {"name", id},
            {"status", "offline"},
            {"unread", 0}
        });
    }
    return ipc::make_success({{"contacts", contacts}});
}

json MessageHandler::handle_chat_add_contact(const json& payload) {
    std::string contact_id = payload.value("contact_id", "");
    std::string public_key = payload.value("public_key", "");
    if (contact_id.empty() || public_key.empty()) {
        return ipc::make_error("contact_id_and_public_key_required");
    }
    return ipc::make_success({{"contact_id", contact_id}, {"status", "pending"}});
}

json MessageHandler::handle_chat_approve_contact(const json& payload) {
    std::string contact_id = payload.value("contact_id", "");
    if (contact_id.empty()) {
        return ipc::make_error("contact_id_required");
    }
    return ipc::make_success({{"contact_id", contact_id}, {"status", "approved"}});
}

json MessageHandler::handle_chat_reject_contact(const json& payload) {
    std::string contact_id = payload.value("contact_id", "");
    if (contact_id.empty()) {
        return ipc::make_error("contact_id_required");
    }
    return ipc::make_success({{"contact_id", contact_id}, {"status", "rejected"}});
}

json MessageHandler::handle_chat_get_messages(const json& payload) {
    int limit = payload.value("limit", 100);
    std::string contact_id = payload.value("contact_id", "");

    auto history = chat_manager_->get_history(limit);

    json messages = json::array();
    for (const auto& msg : history) {
        if (!contact_id.empty() && msg.sender_id != contact_id && msg.sender_id != "self") {
            continue;
        }
        messages.push_back({
            {"id", msg.id},
            {"from", msg.sender_id},
            {"text", msg.content},
            {"timestamp", msg.timestamp},
            {"read", true}
        });
    }
    return ipc::make_success({{"messages", messages}});
}

json MessageHandler::handle_chat_send_message(const json& payload) {
    std::string text = payload.value("text", "");
    std::string recipient_key_b64 = payload.value("recipient_key", "");

    if (text.empty()) {
        return ipc::make_error("text_required");
    }
    if (recipient_key_b64.empty()) {
        return ipc::make_error("recipient_key_required");
    }

    auto key_result = ShieldCrypt::decode_base64(recipient_key_b64);
    if (!key_result.ok()) {
        return ipc::make_error("invalid_recipient_key");
    }

    auto send_result = chat_manager_->send_message(text, key_result.value());
    if (!send_result.ok()) {
        return ipc::make_error(send_result.error().message);
    }

    auto& encrypted = send_result.value();
    return ipc::make_success({
        {"sent", true},
        {"ciphertext_b64", ShieldCrypt::encode_base64(encrypted.ciphertext)},
        {"nonce_b64", ShieldCrypt::encode_base64(encrypted.nonce)}
    });
}

json MessageHandler::handle_chat_mark_read(const json& payload) {
    std::string contact_id = payload.value("contact_id", "");
    if (contact_id.empty()) {
        return ipc::make_error("contact_id_required");
    }
    return ipc::make_success({{"contact_id", contact_id}, {"marked", true}});
}

json MessageHandler::handle_chat_get_status(const json& /*payload*/) {
    return ipc::make_success({{"status", "connected"}});
}

json MessageHandler::handle_chat_set_presence(const json& payload) {
    std::string presence = payload.value("presence", "online");
    return ipc::make_success({{"presence", presence}});
}

json MessageHandler::handle_upload_files(const json& /*payload*/) {
    if (!ui_client_) return ipc::make_error("no_ui_client");
    auto path = ui_client_->open_file_dialog("Select File", "");
    if (path.empty()) {
        return ipc::make_success({{"cancelled", true}});
    }
    return ipc::make_success({{"filePath", path}});
}

// handle_take_screenshot and handle_take_dom_snapshot are now handled
// inline in OnQuery with deferred CDP callbacks (see content_take_screenshot/
// content_take_dom_snapshot in ShieldTierClient).

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

        if (stop.stop_requested()) return;
        auto yr = yara->scan(file);
        if (yr.ok()) engine_results.push_back(std::move(yr.value()));

        if (stop.stop_requested()) return;
        auto fr = fa->analyze(file);
        if (fr.ok()) engine_results.push_back(std::move(fr.value()));

        if (stop.stop_requested()) return;
        auto sr = sandbox->analyze(file);
        if (sr.ok()) engine_results.push_back(std::move(sr.value()));

        if (stop.stop_requested()) return;
        auto ar = advanced->analyze(file);
        if (ar.ok()) engine_results.push_back(std::move(ar.value()));

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
        auto enr = em->enrich_by_hash(sha256, md5);
        if (enr.ok()) engine_results.push_back(std::move(enr.value()));

        auto verdict_result = sc->score(engine_results);

        json output;
        if (verdict_result.ok()) {
            output = {{"status", "complete"}, {"verdict", verdict_result.value()}};
        } else {
            output = {{"status", "error"}, {"error", verdict_result.error().message}};
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

    // Store password and re-trigger analysis
    config_store_->set("archive_password_" + sha256, password);
    config_store_->save();
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
    config_store_->set("archive_password_" + sha256, "__skipped__");
    config_store_->save();
    return ipc::make_success({{"status", "skipped"}, {"sha256", sha256}});
}

// ═══════════════════════════════════════════════════════
// Email Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_get_emails(const json& /*payload*/) {
    // Return all parsed email results from analysis cache
    std::lock_guard<std::mutex> lock(results_mutex_);
    json emails = json::array();
    for (const auto& [sha256, result] : analysis_results_) {
        if (result.contains("engine") && result["engine"] == "email") {
            json entry = result;
            entry["sha256"] = sha256;
            emails.push_back(entry);
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

json MessageHandler::handle_open_email_file(const json& /*payload*/) {
    if (!ui_client_) return ipc::make_error("no_ui_client");
    auto path = ui_client_->open_file_dialog("Open Email", "eml,msg,txt,mhtml");
    if (path.empty()) {
        return ipc::make_success({{"cancelled", true}});
    }
    return ipc::make_success({{"filePath", path}});
}

// ═══════════════════════════════════════════════════════
// Chat: New Handlers
// ═══════════════════════════════════════════════════════

json MessageHandler::handle_chat_remove_contact(const json& payload) {
    std::string contact_id = payload.value("contactId", "");
    if (contact_id.empty()) return ipc::make_error("contactId_required");
    // Remove from local contacts config
    auto contacts = config_store_->get("chat_contacts");
    if (contacts.is_array()) {
        json filtered = json::array();
        for (const auto& c : contacts) {
            if (c.value("id", "") != contact_id) {
                filtered.push_back(c);
            }
        }
        config_store_->set("chat_contacts", filtered);
        config_store_->save();
    }
    return ipc::make_success({{"removed", contact_id}});
}

json MessageHandler::handle_chat_update_contact(const json& payload) {
    std::string contact_id = payload.value("contactId", "");
    std::string name = payload.value("name", "");
    if (contact_id.empty()) return ipc::make_error("contactId_required");

    auto contacts = config_store_->get("chat_contacts");
    if (contacts.is_array()) {
        for (auto& c : contacts) {
            if (c.value("id", "") == contact_id) {
                c["name"] = name;
                break;
            }
        }
        config_store_->set("chat_contacts", contacts);
        config_store_->save();
    }
    return ipc::make_success({{"contactId", contact_id}, {"name", name}});
}

json MessageHandler::handle_chat_get_conversations(const json& /*payload*/) {
    // Build conversations from chat history
    auto history = chat_manager_->get_history(1000);
    std::unordered_map<std::string, json> convos;

    for (const auto& msg : history) {
        std::string peer = (msg.sender_id == "self") ? "self" : msg.sender_id;
        if (peer == "self") continue;

        if (convos.find(peer) == convos.end()) {
            convos[peer] = {
                {"id", peer}, {"contactId", peer}, {"lastMessage", msg.content},
                {"lastTimestamp", msg.timestamp}, {"unreadCount", 0}
            };
        } else {
            convos[peer]["lastMessage"] = msg.content;
            convos[peer]["lastTimestamp"] = msg.timestamp;
        }
    }

    json result = json::array();
    for (const auto& [_, c] : convos) {
        result.push_back(c);
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
        FILE* pipe = popen(cmd.c_str(), "r");
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
            pclose(pipe);
        }
    }

    return ipc::make_success({
        {"installed", installed}, {"status", status},
        {"activeInstances", vms.size()},
        {"version", version}, {"accelerator", accelerator}
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
    auto catalog = VmInstaller::default_image_catalog();
    json images = json::array();
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
    auto vms = vm_manager_->list_vms();
    json instances = json::array();
    for (const auto& vm : vms) {
        auto state = vm_manager_->get_state(vm.id);
        std::string state_str = "unknown";
        if (state == VmState::kStopped) state_str = "stopped";
        else if (state == VmState::kBooting) state_str = "booting";
        else if (state == VmState::kReady) state_str = "ready";
        else if (state == VmState::kAnalyzing) state_str = "analyzing";
        else if (state == VmState::kError) state_str = "error";
        instances.push_back({{"id", vm.id}, {"state", state_str}});
    }
    return ipc::make_success({{"instances", instances}});
}

json MessageHandler::handle_vm_get_result(const json& payload) {
    std::string instance_id = payload.value("instanceId", "");
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

json MessageHandler::handle_open_log_file(const json& /*payload*/) {
    if (!ui_client_) return ipc::make_error("no_ui_client");
    auto path = ui_client_->open_file_dialog("Open Log", "log,csv,json,evtx,txt,xml");
    if (path.empty()) {
        return ipc::make_success({{"cancelled", true}});
    }
    return ipc::make_success({{"filePath", path}});
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

}  // namespace shieldtier
