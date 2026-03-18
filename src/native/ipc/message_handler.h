#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "include/cef_browser.h"
#include "include/wrapper/cef_message_router.h"

#include "ipc/event_bridge.h"

#include "analysis/enrichment/http_client.h"
#include "analysis/yara/yara_engine.h"
#include "analysis/fileanalysis/file_analyzer.h"
#include "analysis/enrichment/enrichment_manager.h"
#include "analysis/sandbox/sandbox_engine.h"
#include "analysis/advanced/advanced_engine.h"
#include "analysis/email/email_analyzer.h"
#include "analysis/content/content_analyzer.h"
#include "analysis/loganalysis/log_manager.h"
#include "analysis/loganalysis/log_normalizer.h"
#include "analysis/loganalysis/log_analysis_engine.h"
#include "analysis/threatfeed/threat_feed_manager.h"
#include "browser/session_manager.h"
#include "chat/chat_manager.h"
#include "capture/capture_manager.h"
#include "analysis/sandbox/cloud_sandbox.h"
#include "capture/har_builder.h"
#include "config/config_store.h"
#include "export/export_manager.h"
#include "ipc/ipc_protocol.h"
#include "scoring/scoring_engine.h"
#include "vm/vm_manager.h"
#include "vm/vm_installer.h"

class ShieldTierClient;

namespace shieldtier {

class MessageHandler : public CefMessageRouterBrowserSide::Handler {
public:
    explicit MessageHandler(SessionManager* session_manager);
    ~MessageHandler();

    bool OnQuery(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                 int64_t query_id, const CefString& request, bool persistent,
                 CefRefPtr<Callback> callback) override;

    void OnQueryCanceled(CefRefPtr<CefBrowser> browser,
                         CefRefPtr<CefFrame> frame,
                         int64_t query_id) override;

    void set_event_bridge(EventBridge* bridge) { event_bridge_ = bridge; }
    void set_ui_client(ShieldTierClient* client) { ui_client_ = client; }
    void auto_analyze(const std::string& sha256);
    CaptureManager* capture_manager() { return capture_manager_.get(); }
    ThreatFeedManager* threat_feed_manager() { return threat_feed_manager_.get(); }
    ContentAnalyzer* content_analyzer() { return content_analyzer_.get(); }

private:
    json handle_navigate(CefRefPtr<CefBrowser> browser, const json& payload);
    json handle_get_tabs(const json& payload);
    json handle_close_tab(const json& payload);
    json handle_analyze_download(const json& payload);
    json handle_get_analysis_result(const json& payload);
    json handle_get_config(const json& payload);
    json handle_set_config(const json& payload);
    json handle_export_report(const json& payload);
    json handle_get_threat_feeds(const json& payload);
    json handle_start_capture(const json& payload);
    json handle_stop_capture(const json& payload);
    json handle_get_capture(const json& payload);
    json handle_nav_back(const json& payload);
    json handle_nav_forward(const json& payload);
    json handle_nav_reload(const json& payload);
    json handle_nav_stop(const json& payload);
    json handle_set_content_bounds(const json& payload);
    json handle_hide_content_browser(const json& payload);
    json handle_set_zoom(const json& payload);
    json handle_get_zoom(const json& payload);
    json handle_start_vm(const json& payload);
    json handle_stop_vm(const json& payload);
    json handle_submit_sample_to_vm(const json& payload);
    json handle_analyze_email(const json& payload);
    json handle_analyze_logs(const json& payload);
    json handle_get_log_results(const json& payload);
    json handle_upload_files(const json& payload);
    // take_screenshot / take_dom_snapshot handled inline in OnQuery (deferred CDP)

    // Auth handlers
    json handle_auth_login(const json& payload);
    json handle_auth_register(const json& payload);
    json handle_auth_logout(const json& payload);
    json handle_auth_get_user(const json& payload);
    json handle_auth_restore_session(const json& payload);
    json handle_auth_change_password(const json& payload);
    json handle_auth_resend_verification(const json& payload);
    json handle_auth_refresh_profile(const json& payload);
    json handle_auth_update_profile(const json& payload);
    json handle_auth_sync_cases(const json& payload);
    json handle_auth_get_cases(const json& payload);
    json handle_auth_set_sync_key(const json& payload);

    // Auth HTTP helpers
    json auth_api_post(const std::string& path, const json& body);
    json auth_api_get(const std::string& path);
    void auth_persist();
    void auth_clear();

    json handle_chat_get_identity(const json& payload);
    json handle_chat_get_contacts(const json& payload);
    json handle_chat_add_contact(const json& payload);
    json handle_chat_approve_contact(const json& payload);
    json handle_chat_reject_contact(const json& payload);
    json handle_chat_get_messages(const json& payload);
    json handle_chat_send_message(const json& payload);
    json handle_chat_mark_read(const json& payload);
    json handle_chat_get_status(const json& payload);
    json handle_chat_set_presence(const json& payload);
    json handle_chat_remove_contact(const json& payload);
    json handle_chat_update_contact(const json& payload);
    json handle_chat_get_conversations(const json& payload);
    json handle_chat_lookup_user(const json& payload);
    json handle_chat_ack_onboarding(const json& payload);
    json handle_chat_get_requests(const json& payload);

    // View / Nav state
    json handle_get_nav_state(const json& payload);
    json handle_analyze_now(const json& payload);

    // Config
    json handle_check_whitelist(const json& payload);

    // YARA
    json handle_yara_get_rules(const json& payload);
    json handle_yara_get_rule(const json& payload);
    json handle_yara_add_rule(const json& payload);
    json handle_yara_update_rule(const json& payload);
    json handle_yara_delete_rule(const json& payload);
    json handle_yara_import_rules(const json& payload);
    json handle_yara_export_rules(const json& payload);
    json handle_yara_get_packs(const json& payload);
    json handle_yara_toggle_pack(const json& payload);
    json handle_yara_scan_file(const json& payload);
    json handle_yara_scan_content(const json& payload);
    json handle_yara_get_results(const json& payload);

    // File Analysis
    json handle_delete_file(const json& payload);
    json handle_submit_archive_password(const json& payload);
    json handle_skip_archive_password(const json& payload);

    // Email
    json handle_get_emails(const json& payload);
    json handle_get_email(const json& payload);
    json handle_open_email_file(const json& payload);

    // Threat Feed
    json handle_threatfeed_add(const json& payload);
    json handle_threatfeed_update(const json& payload);
    json handle_threatfeed_delete(const json& payload);
    json handle_threatfeed_toggle(const json& payload);
    json handle_threatfeed_discover(const json& payload);
    json handle_threatfeed_collections(const json& payload);
    json handle_threatfeed_sync(const json& payload);
    json handle_threatfeed_sync_all(const json& payload);
    json handle_threatfeed_matches(const json& payload);
    json handle_threatfeed_import_csv(const json& payload);
    json handle_threatfeed_import_stix(const json& payload);
    json handle_threatfeed_stats(const json& payload);

    // VM
    json handle_vm_get_status(const json& payload);
    json handle_vm_install(const json& payload);
    json handle_vm_list_images(const json& payload);
    json handle_vm_download_image(const json& payload);
    json handle_vm_get_instances(const json& payload);
    json handle_vm_get_result(const json& payload);
    json handle_vm_has_snapshot(const json& payload);
    json handle_vm_prepare_snapshot(const json& payload);
    json handle_vm_get_ca_cert(const json& payload);
    json handle_vm_build_agent(const json& payload);
    json handle_vm_get_agent_status(const json& payload);

    // Log Analysis
    json handle_get_log_result(const json& payload);
    json handle_delete_log_result(const json& payload);
    json handle_get_log_formats(const json& payload);
    json handle_open_log_file(const json& payload);

    // Capture
    json handle_get_capture_status(const json& payload);
    json handle_get_screenshots(const json& payload);
    json handle_get_dom_snapshots(const json& payload);

    // Content Analysis
    json handle_get_content_findings(const json& payload);

    // Proxy
    json handle_test_proxy(const json& payload);

    // Report
    json handle_preview_report(const json& payload);
    json handle_save_report(const json& payload);

    // Enrichment
    json handle_enrichment_query(const json& payload);
    json handle_enrichment_get_results(const json& payload);

    // Sessions
    json handle_session_create(const json& payload);
    json handle_session_destroy(const json& payload);
    json handle_session_list(const json& payload);

    // Cloud Sandbox
    json handle_cloud_sandbox_submit(const json& payload);
    json handle_cloud_sandbox_poll(const json& payload);

    // URL Chain Investigation
    json handle_investigate_url(const json& payload);
    json handle_get_url_chains(const json& payload);

    // Document Preview
    json handle_get_file_preview(const json& payload);
    std::unordered_map<std::string, json> url_chains_;  // chainId → chain result

    SessionManager* session_manager_;
    EventBridge* event_bridge_ = nullptr;
    ShieldTierClient* ui_client_ = nullptr;
    std::unordered_map<std::string, json> analysis_results_;
    std::mutex results_mutex_;

    std::unique_ptr<YaraEngine> yara_engine_;
    std::unique_ptr<FileAnalyzer> file_analyzer_;
    std::unique_ptr<EnrichmentManager> enrichment_manager_;
    std::unique_ptr<ScoringEngine> scoring_engine_;
    std::unique_ptr<SandboxEngine> sandbox_engine_;
    std::unique_ptr<AdvancedEngine> advanced_engine_;
    std::unique_ptr<EmailAnalyzer> email_analyzer_;
    std::unique_ptr<ContentAnalyzer> content_analyzer_;
    std::unique_ptr<LogManager> log_manager_;
    std::unique_ptr<LogAnalysisEngine> log_analysis_engine_;
    std::unique_ptr<ThreatFeedManager> threat_feed_manager_;
    std::unique_ptr<CaptureManager> capture_manager_;
    std::unique_ptr<ConfigStore> config_store_;
    std::unique_ptr<ExportManager> export_manager_;
    std::unique_ptr<VmManager> vm_manager_;
    std::unique_ptr<VmInstaller> vm_installer_;
    std::unique_ptr<ChatManager> chat_manager_;
    std::unique_ptr<CloudSandboxManager> cloud_sandbox_;
    HarBuilder har_builder_;

    std::vector<std::jthread> analysis_threads_;
    std::mutex threads_mutex_;
    std::atomic<bool> vm_download_cancel_{false};

    // Auth state
    std::unique_ptr<HttpClient> auth_http_;
    std::string auth_access_token_;
    std::string auth_refresh_token_;
    int64_t auth_token_expires_at_ = 0;
    json auth_user_ = nullptr;  // cached user object
    std::mutex auth_mutex_;
    static constexpr const char* kAuthApiUrl = "https://api.socbrowser.com";
};

}  // namespace shieldtier
