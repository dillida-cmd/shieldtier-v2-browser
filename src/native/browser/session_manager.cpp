#include "browser/session_manager.h"

#include <filesystem>
#include <optional>

#include "include/cef_cookie.h"
#include "include/cef_request_context_handler.h"

#if defined(OS_MAC)
#include "app/app_mac.h"
#endif

namespace shieldtier {

SessionManager::SessionManager(const std::string& root_cache_path)
    : root_cache_path_(root_cache_path) {}

void SessionManager::set_parent_view(void* view, int width, int height) {
    parent_view_ = view;
    parent_width_ = width;
    parent_height_ = height;
}

void SessionManager::set_scheme_handler(const std::string& scheme,
                                        const std::string& domain,
                                        CefRefPtr<CefSchemeHandlerFactory> factory) {
    scheme_name_ = scheme;
    scheme_domain_ = domain;
    scheme_factory_ = factory;
}

void SessionManager::create_tab(const std::string& url, bool in_memory,
                                CefRefPtr<CefClient> client,
                                const std::string& proxy_rules) {
    int tab_id = next_tab_id_++;

    CefRequestContextSettings ctx_settings;
    if (!in_memory) {
        std::string cache_path = root_cache_path_ + "/tab_" + std::to_string(tab_id);
        CefString(&ctx_settings.cache_path) = cache_path;
    }

    CefRefPtr<CefRequestContext> context =
        CefRequestContext::CreateContext(ctx_settings, nullptr);

    // Apply per-session proxy rules if provided.
    // Format: "socks5://host:port" or "http://host:port" or "direct://"
    if (!proxy_rules.empty()) {
        CefRefPtr<CefValue> proxy_val = CefValue::Create();
        CefRefPtr<CefDictionaryValue> proxy_dict = CefDictionaryValue::Create();
        proxy_dict->SetString("mode", "fixed_servers");
        proxy_dict->SetString("server", proxy_rules);
        proxy_val->SetDictionary(proxy_dict);
        CefString error;
        context->SetPreference("proxy", proxy_val, error);
        if (!error.empty()) {
            fprintf(stderr, "[ShieldTier] Per-session proxy error: %s\n",
                    error.ToString().c_str());
        } else {
            fprintf(stderr, "[ShieldTier] Per-session proxy set: %s\n",
                    proxy_rules.c_str());
        }
    }

    if (scheme_factory_) {
        context->RegisterSchemeHandlerFactory(scheme_name_, scheme_domain_,
                                              scheme_factory_);
    }

    CefWindowInfo window_info;
    window_info.runtime_style = CEF_RUNTIME_STYLE_ALLOY;
#if defined(OS_MAC)
    fprintf(stderr, "[ShieldTier] parent_view=%p, size=%dx%d\n",
            parent_view_, parent_width_, parent_height_);
    if (parent_view_) {
        window_info.SetAsChild(parent_view_,
                               CefRect(0, 0, parent_width_, parent_height_));
    }
#elif defined(OS_WIN)
    window_info.SetAsPopup(nullptr, "ShieldTier");
#endif

    CefBrowserSettings browser_settings;

    TabInfo info;
    info.tab_id = tab_id;
    info.context = context;
    info.in_memory = in_memory;

    pending_tabs_[tab_id] = info;

    bool result = CefBrowserHost::CreateBrowser(window_info, client, url,
                                                browser_settings, nullptr, context);
    if (!result) {
        fprintf(stderr, "[ShieldTier] CreateBrowser FAILED for url: %s\n", url.c_str());
        pending_tabs_.erase(tab_id);
    } else {
        fprintf(stderr, "[ShieldTier] CreateBrowser OK for url: %s\n", url.c_str());
    }
}

void SessionManager::close_tab(int browser_id) {
    auto it = cef_id_to_tab_id_.find(browser_id);
    if (it == cef_id_to_tab_id_.end()) {
        return;
    }

    auto tab_it = tabs_.find(it->second);
    if (tab_it != tabs_.end() && tab_it->second.browser) {
        tab_it->second.browser->GetHost()->CloseBrowser(true);
        tab_it->second.browser = nullptr;
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

std::optional<FileBuffer> SessionManager::get_captured_download(
        const std::string& sha256) {
    std::lock_guard<std::mutex> lock(captured_mutex_);
    auto it = captured_files_.find(sha256);
    if (it == captured_files_.end()) return std::nullopt;
    return it->second;
}

void SessionManager::store_captured_file(const std::string& sha256,
                                          std::vector<uint8_t>&& data,
                                          const std::string& filename,
                                          const std::string& mime_type) {
    FileBuffer fb;
    fb.data = std::move(data);
    fb.filename = filename;
    fb.mime_type = mime_type;
    fb.sha256 = sha256;

    std::lock_guard<std::mutex> lock(captured_mutex_);
    captured_files_[sha256] = std::move(fb);
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

    CefRefPtr<CefRequestContext> browser_ctx =
        browser->GetHost()->GetRequestContext();
    for (auto it = pending_tabs_.begin(); it != pending_tabs_.end(); ++it) {
        if (browser_ctx && browser_ctx->IsSame(it->second.context)) {
            TabInfo info = it->second;
            info.browser_id = cef_id;
            info.browser = browser;

#if defined(OS_MAC)
            // Only the UI browser (our managed tabs) gets autoresizing to fill the window.
            // The content browser is positioned manually via set_content_bounds.
            void* view = browser->GetHost()->GetWindowHandle();
            if (view) {
                shieldtier_mac_set_view_autoresizing(view);
            }
#endif

            tabs_[info.tab_id] = info;
            cef_id_to_tab_id_[cef_id] = info.tab_id;
            pending_tabs_.erase(it);
            return;
        }
    }

    // Unrecognized context — track with a synthetic tab id
    int tab_id = next_tab_id_++;
    TabInfo info;
    info.tab_id = tab_id;
    info.browser_id = cef_id;
    info.browser = browser;
    info.context = browser_ctx;
    // Derive in_memory from whether the context has a cache path set
    CefString cache_path = browser_ctx ? browser_ctx->GetCachePath() : CefString();
    info.in_memory = cache_path.empty();

    tabs_[tab_id] = info;
    cef_id_to_tab_id_[cef_id] = tab_id;
}

void SessionManager::on_browser_closed(CefRefPtr<CefBrowser> browser) {
    int cef_id = browser->GetIdentifier();

    auto it = cef_id_to_tab_id_.find(cef_id);
    if (it == cef_id_to_tab_id_.end()) {
        return;
    }

    int tab_id = it->second;
    auto tab_it = tabs_.find(tab_id);

    // Clean up on-disk cache for non-in-memory tabs
    if (tab_it != tabs_.end() && !tab_it->second.in_memory) {
        std::string cache_path = root_cache_path_ + "/tab_" + std::to_string(tab_id);
        std::error_code ec;
        std::filesystem::remove_all(cache_path, ec);
    }

    if (tab_it != tabs_.end()) {
        tabs_.erase(tab_it);
    }
    cef_id_to_tab_id_.erase(it);
}

// ═══════════════════════════════════════════════════════
// Investigation Session Management (main-process state)
// ═══════════════════════════════════════════════════════

std::string SessionManager::get_next_case_id() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    int id = next_case_counter_++;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "CASE-%06d", id);
    return buf;
}

void SessionManager::set_next_case_counter(int counter) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    next_case_counter_ = counter;
}

InvestigationSession SessionManager::create_session(
    const std::string& case_name,
    const std::string& url,
    const json& proxy_config) {
    InvestigationSession session;
    // Generate unique session ID
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    session.id = "sess-" + std::to_string(now) + "-" +
                 std::to_string(next_tab_id_);
    session.case_id = get_next_case_id();
    session.case_name = case_name.empty() ? "Untitled" : case_name;
    session.created_at = now;
    session.url = url;
    session.partition = "isolated-" + session.id;
    session.proxy_config = proxy_config;

    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_[session.id] = session;
    return session;
}

void SessionManager::destroy_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.erase(session_id);
}

std::vector<InvestigationSession> SessionManager::list_sessions() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    std::vector<InvestigationSession> result;
    result.reserve(sessions_.size());
    for (const auto& [id, session] : sessions_) {
        result.push_back(session);
    }
    return result;
}

InvestigationSession* SessionManager::get_session(
    const std::string& session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return nullptr;
    return &it->second;
}

void SessionManager::update_nav_state(const std::string& session_id,
                                       bool can_back, bool can_forward,
                                       bool loading, const std::string& url) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return;
    it->second.can_go_back = can_back;
    it->second.can_go_forward = can_forward;
    it->second.is_loading = loading;
    if (!url.empty()) {
        it->second.current_url = url;
        it->second.url = url;
    }
}

}  // namespace shieldtier
