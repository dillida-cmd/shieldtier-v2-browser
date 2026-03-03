#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "include/cef_browser.h"
#include "include/wrapper/cef_message_router.h"

#include "analysis/yara/yara_engine.h"
#include "analysis/fileanalysis/file_analyzer.h"
#include "analysis/enrichment/enrichment_manager.h"
#include "browser/session_manager.h"
#include "ipc/ipc_protocol.h"
#include "scoring/scoring_engine.h"

namespace shieldtier {

class MessageHandler : public CefMessageRouterBrowserSide::Handler {
public:
    explicit MessageHandler(SessionManager* session_manager);

    bool OnQuery(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                 int64_t query_id, const CefString& request, bool persistent,
                 CefRefPtr<Callback> callback) override;

    void OnQueryCanceled(CefRefPtr<CefBrowser> browser,
                         CefRefPtr<CefFrame> frame,
                         int64_t query_id) override;

private:
    json handle_navigate(CefRefPtr<CefBrowser> browser, const json& payload);
    json handle_get_tabs(const json& payload);
    json handle_close_tab(const json& payload);
    json handle_analyze_download(const json& payload);
    json handle_get_analysis_result(const json& payload);

    SessionManager* session_manager_;
    std::unordered_map<std::string, json> analysis_results_;
    std::mutex results_mutex_;

    std::unique_ptr<YaraEngine> yara_engine_;
    std::unique_ptr<FileAnalyzer> file_analyzer_;
    std::unique_ptr<EnrichmentManager> enrichment_manager_;
    std::unique_ptr<ScoringEngine> scoring_engine_;
};

}  // namespace shieldtier
