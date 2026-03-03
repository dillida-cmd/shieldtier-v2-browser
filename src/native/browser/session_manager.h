#pragma once

#include <optional>
#include <string>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "include/cef_browser.h"
#include "include/cef_client.h"
#include "include/cef_request_context.h"

#include "common/types.h"

namespace shieldtier {

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

    void create_tab(const std::string& url, bool in_memory,
                    CefRefPtr<CefClient> client);
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
    int next_tab_id_ = 1;
    std::unordered_map<int, TabInfo> tabs_;
    std::unordered_map<int, int> cef_id_to_tab_id_;

    // Pending tabs waiting for CEF to assign a browser ID.
    // Keyed by our internal tab_id since we don't have the CEF ID yet.
    std::unordered_map<int, TabInfo> pending_tabs_;

    std::unordered_map<std::string, FileBuffer> captured_files_;
    std::mutex captured_mutex_;
};

}  // namespace shieldtier
