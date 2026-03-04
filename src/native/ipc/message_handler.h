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

#include "analysis/yara/yara_engine.h"
#include "analysis/fileanalysis/file_analyzer.h"
#include "analysis/enrichment/enrichment_manager.h"
#include "analysis/sandbox/sandbox_engine.h"
#include "analysis/advanced/advanced_engine.h"
#include "analysis/email/email_analyzer.h"
#include "analysis/content/content_analyzer.h"
#include "analysis/loganalysis/log_manager.h"
#include "analysis/threatfeed/threat_feed_manager.h"
#include "browser/session_manager.h"
#include "capture/capture_manager.h"
#include "capture/har_builder.h"
#include "config/config_store.h"
#include "export/export_manager.h"
#include "ipc/ipc_protocol.h"
#include "scoring/scoring_engine.h"

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
    void auto_analyze(const std::string& sha256);

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
    json handle_nav_back(CefRefPtr<CefBrowser> browser, const json& payload);
    json handle_nav_forward(CefRefPtr<CefBrowser> browser, const json& payload);
    json handle_nav_reload(CefRefPtr<CefBrowser> browser, const json& payload);
    json handle_nav_stop(CefRefPtr<CefBrowser> browser, const json& payload);

    SessionManager* session_manager_;
    EventBridge* event_bridge_ = nullptr;
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
    std::unique_ptr<ThreatFeedManager> threat_feed_manager_;
    std::unique_ptr<CaptureManager> capture_manager_;
    std::unique_ptr<ConfigStore> config_store_;
    std::unique_ptr<ExportManager> export_manager_;
    HarBuilder har_builder_;

    std::vector<std::jthread> analysis_threads_;
    std::mutex threads_mutex_;
};

}  // namespace shieldtier
