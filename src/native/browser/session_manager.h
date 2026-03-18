#pragma once

#include <optional>
#include <string>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "include/cef_browser.h"
#include "include/cef_client.h"
#include "include/cef_request_context.h"
#include "include/cef_scheme.h"

#include "common/types.h"
#include "common/json.h"

namespace shieldtier {

/// Investigation session state — survives renderer crashes.
/// Mirrors V1's InvestigationSession managed in the Electron main process.
struct InvestigationSession {
    std::string id;
    std::string case_id;
    std::string case_name;
    int64_t created_at = 0;
    std::string url;
    std::string partition;

    // Navigation state
    bool can_go_back = false;
    bool can_go_forward = false;
    bool is_loading = false;
    std::string current_url;

    // Per-session proxy (empty = use global)
    json proxy_config = nullptr;
};

class SessionManager {
public:
    explicit SessionManager(const std::string& root_cache_path);

    struct TabInfo {
        int tab_id = 0;
        int browser_id = 0;
        CefRefPtr<CefBrowser> browser;
        CefRefPtr<CefRequestContext> context;
        bool in_memory = false;
    };

    // ── Investigation session management ──
    InvestigationSession create_session(const std::string& case_name,
                                         const std::string& url,
                                         const json& proxy_config);
    void destroy_session(const std::string& session_id);
    std::vector<InvestigationSession> list_sessions() const;
    InvestigationSession* get_session(const std::string& session_id);
    void update_nav_state(const std::string& session_id,
                          bool can_back, bool can_forward,
                          bool loading, const std::string& url);
    std::string get_next_case_id();
    void set_next_case_counter(int counter);

    void set_parent_view(void* view, int width, int height);

    void set_scheme_handler(const std::string& scheme,
                            const std::string& domain,
                            CefRefPtr<CefSchemeHandlerFactory> factory);

    void create_tab(const std::string& url, bool in_memory,
                    CefRefPtr<CefClient> client,
                    const std::string& proxy_rules = "");
    void close_tab(int browser_id);
    CefRefPtr<CefBrowser> get_browser(int browser_id);
    std::vector<TabInfo> get_all_tabs() const;
    void clear_tab_data(int browser_id);

    std::optional<FileBuffer> get_captured_download(const std::string& sha256);

    void store_captured_file(const std::string& sha256,
                             std::vector<uint8_t>&& data,
                             const std::string& filename,
                             const std::string& mime_type);

    void on_browser_created(CefRefPtr<CefBrowser> browser);
    void on_browser_closed(CefRefPtr<CefBrowser> browser);

private:
    std::string root_cache_path_;
    void* parent_view_ = nullptr;
    int parent_width_ = 0;
    int parent_height_ = 0;
    int next_tab_id_ = 1;
    std::unordered_map<int, TabInfo> tabs_;
    std::unordered_map<int, int> cef_id_to_tab_id_;

    // Pending tabs waiting for CEF to assign a browser ID.
    // Keyed by our internal tab_id since we don't have the CEF ID yet.
    std::unordered_map<int, TabInfo> pending_tabs_;

    std::string scheme_name_;
    std::string scheme_domain_;
    CefRefPtr<CefSchemeHandlerFactory> scheme_factory_;

    std::unordered_map<std::string, FileBuffer> captured_files_;
    std::mutex captured_mutex_;

    // Investigation sessions (main-process state, survives renderer crashes)
    mutable std::mutex sessions_mutex_;
    std::unordered_map<std::string, InvestigationSession> sessions_;
    int next_case_counter_ = 1;
};

}  // namespace shieldtier
