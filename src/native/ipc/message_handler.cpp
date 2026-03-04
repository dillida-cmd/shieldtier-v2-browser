#include "ipc/message_handler.h"

#include <thread>

#include "analysis/fileanalysis/file_analyzer.h"
#include "browser/navigation.h"
#include "chat/shieldcrypt.h"

namespace shieldtier {

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
      config_store_(std::make_unique<ConfigStore>("shieldtier.json")),
      export_manager_(std::make_unique<ExportManager>()),
      vm_manager_(std::make_unique<VmManager>("/tmp/shieldtier/vms")),
      chat_manager_(std::make_unique<ChatManager>("/tmp/shieldtier/chat")) {
    chat_manager_->initialize_keys();
    yara_engine_->initialize();
    config_store_->load();
    threat_feed_manager_->update_feeds();
}

MessageHandler::~MessageHandler() {
    // jthread destructor requests stop and joins automatically.
    std::lock_guard<std::mutex> lock(threads_mutex_);
    analysis_threads_.clear();
}

bool MessageHandler::OnQuery(CefRefPtr<CefBrowser> browser,
                             CefRefPtr<CefFrame> /*frame*/,
                             int64_t /*query_id*/,
                             const CefString& request,
                             bool /*persistent*/,
                             CefRefPtr<Callback> callback) {
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
            result = handle_nav_back(browser, req.payload);
        } else if (req.action == ipc::kActionNavForward) {
            result = handle_nav_forward(browser, req.payload);
        } else if (req.action == ipc::kActionNavReload) {
            result = handle_nav_reload(browser, req.payload);
        } else if (req.action == ipc::kActionNavStop) {
            result = handle_nav_stop(browser, req.payload);
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

json MessageHandler::handle_navigate(CefRefPtr<CefBrowser> browser,
                                     const json& payload) {
    std::string url = payload.value("url", "");
    if (url.empty()) {
        return ipc::make_error("url_required");
    }
    if (url.compare(0, 7, "http://") != 0 &&
        url.compare(0, 8, "https://") != 0 &&
        url != "about:blank") {
        return ipc::make_error("invalid_url_scheme");
    }
    Navigation::load_url(browser, url);
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
        return ipc::make_error("sha256_required");
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
    if (sha256.empty()) {
        return ipc::make_error("sha256_required");
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
        {"indicator_count", threat_feed_manager_->indicator_count()}
    });
}

json MessageHandler::handle_start_capture(const json& payload) {
    int browser_id = payload.value("browser_id", -1);
    if (browser_id < 0) {
        return ipc::make_error("browser_id_required");
    }
    capture_manager_->start_capture(browser_id);
    return ipc::make_success();
}

json MessageHandler::handle_stop_capture(const json& payload) {
    int browser_id = payload.value("browser_id", -1);
    if (browser_id < 0) {
        return ipc::make_error("browser_id_required");
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
    if (browser_id < 0) {
        return ipc::make_error("browser_id_required");
    }

    auto requests = capture_manager_->get_requests(browser_id);
    auto har = har_builder_.build_string(requests);

    return ipc::make_success({
        {"capturing", capture_manager_->is_capturing(browser_id)},
        {"request_count", requests.size()},
        {"har", har}
    });
}

json MessageHandler::handle_nav_back(CefRefPtr<CefBrowser> browser,
                                      const json& /*payload*/) {
    Navigation::go_back(browser);
    return ipc::make_success();
}

json MessageHandler::handle_nav_forward(CefRefPtr<CefBrowser> browser,
                                         const json& /*payload*/) {
    Navigation::go_forward(browser);
    return ipc::make_success();
}

json MessageHandler::handle_nav_reload(CefRefPtr<CefBrowser> browser,
                                        const json& /*payload*/) {
    Navigation::reload(browser);
    return ipc::make_success();
}

json MessageHandler::handle_nav_stop(CefRefPtr<CefBrowser> browser,
                                      const json& /*payload*/) {
    Navigation::stop(browser);
    return ipc::make_success();
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
    auto result = vm_manager_->submit_sample(vm_id, file_opt.value());
    if (!result.ok()) {
        return ipc::make_error(result.error().message);
    }

    if (event_bridge_) {
        event_bridge_->push_vm_status("running");
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
        return ipc::make_error("sha256_required");
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
        return ipc::make_error("sha256_required");
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

}  // namespace shieldtier
