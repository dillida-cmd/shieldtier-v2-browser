#include "ipc/message_handler.h"

#include <thread>

#include "analysis/fileanalysis/file_analyzer.h"
#include "browser/navigation.h"

namespace shieldtier {

MessageHandler::MessageHandler(SessionManager* session_manager)
    : session_manager_(session_manager),
      yara_engine_(std::make_unique<YaraEngine>()),
      file_analyzer_(std::make_unique<FileAnalyzer>()),
      enrichment_manager_(std::make_unique<EnrichmentManager>(EnrichmentConfig{})),
      scoring_engine_(std::make_unique<ScoringEngine>()) {
    yara_engine_->initialize();
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
    auto* results_map = &analysis_results_;
    auto* mtx = &results_mutex_;

    std::jthread thread([sha256, sm, yara, fa, em, sc, results_map, mtx]
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

}  // namespace shieldtier
