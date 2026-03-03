#include "browser/session_manager.h"

#include "include/cef_cookie.h"

namespace shieldtier {

SessionManager::SessionManager(const std::string& root_cache_path)
    : root_cache_path_(root_cache_path) {}

void SessionManager::create_tab(const std::string& url, bool in_memory,
                                CefRefPtr<CefClient> client) {
    int tab_id = next_tab_id_++;

    CefRequestContextSettings ctx_settings;
    if (!in_memory) {
        std::string cache_path = root_cache_path_ + "/tab_" + std::to_string(tab_id);
        CefString(&ctx_settings.cache_path) = cache_path;
    }

    CefRefPtr<CefRequestContext> context =
        CefRequestContext::CreateContext(ctx_settings, nullptr);

    CefWindowInfo window_info;
#if defined(OS_WIN)
    window_info.SetAsPopup(nullptr, "ShieldTier");
#endif

    CefBrowserSettings browser_settings;

    TabInfo info;
    info.tab_id = tab_id;
    info.context = context;
    info.in_memory = in_memory;

    pending_tabs_[tab_id] = info;

    CefBrowserHost::CreateBrowser(window_info, client, url,
                                  browser_settings, nullptr, context);
}

void SessionManager::close_tab(int browser_id) {
    auto it = cef_id_to_tab_id_.find(browser_id);
    if (it == cef_id_to_tab_id_.end()) {
        return;
    }

    auto tab_it = tabs_.find(it->second);
    if (tab_it != tabs_.end() && tab_it->second.browser) {
        tab_it->second.browser->GetHost()->CloseBrowser(true);
    }
}

CefRefPtr<CefBrowser> SessionManager::get_browser(int browser_id) {
    auto it = cef_id_to_tab_id_.find(browser_id);
    if (it == cef_id_to_tab_id_.end()) {
        return nullptr;
    }

    auto tab_it = tabs_.find(it->second);
    if (tab_it == tabs_.end()) {
        return nullptr;
    }
    return tab_it->second.browser;
}

std::vector<SessionManager::TabInfo> SessionManager::get_all_tabs() const {
    std::vector<TabInfo> result;
    result.reserve(tabs_.size());
    for (const auto& [id, info] : tabs_) {
        result.push_back(info);
    }
    return result;
}

void SessionManager::clear_tab_data(int browser_id) {
    auto it = cef_id_to_tab_id_.find(browser_id);
    if (it == cef_id_to_tab_id_.end()) {
        return;
    }

    auto tab_it = tabs_.find(it->second);
    if (tab_it == tabs_.end()) {
        return;
    }

    CefRefPtr<CefRequestContext> ctx = tab_it->second.context;
    if (!ctx) {
        return;
    }

    CefRefPtr<CefCookieManager> cookie_mgr = ctx->GetCookieManager(nullptr);
    if (cookie_mgr) {
        cookie_mgr->DeleteCookies("", "", nullptr);
    }
}

void SessionManager::on_browser_created(CefRefPtr<CefBrowser> browser) {
    int cef_id = browser->GetIdentifier();

    // Match to pending tab by comparing request contexts. Each tab gets a
    // unique CefRequestContext, so IsSame() is a reliable correlator even
    // when multiple CreateBrowser calls are in-flight concurrently.
    CefRefPtr<CefRequestContext> browser_ctx =
        browser->GetHost()->GetRequestContext();
    for (auto it = pending_tabs_.begin(); it != pending_tabs_.end(); ++it) {
        if (browser_ctx && browser_ctx->IsSame(it->second.context)) {
            TabInfo info = it->second;
            info.browser = browser;
            info.browser_id = cef_id;

            tabs_[info.tab_id] = info;
            cef_id_to_tab_id_[cef_id] = info.tab_id;
            pending_tabs_.erase(it);
            return;
        }
    }

    // Fallback: if no pending tab matched (e.g. browser opened externally),
    // track it with a synthetic tab id.
    int tab_id = next_tab_id_++;
    TabInfo info;
    info.tab_id = tab_id;
    info.browser_id = cef_id;
    info.browser = browser;
    info.context = browser->GetHost()->GetRequestContext();
    info.in_memory = true;

    tabs_[tab_id] = info;
    cef_id_to_tab_id_[cef_id] = tab_id;
}

void SessionManager::on_browser_closed(CefRefPtr<CefBrowser> browser) {
    int cef_id = browser->GetIdentifier();

    auto it = cef_id_to_tab_id_.find(cef_id);
    if (it == cef_id_to_tab_id_.end()) {
        return;
    }

    tabs_.erase(it->second);
    cef_id_to_tab_id_.erase(it);
}

}  // namespace shieldtier
