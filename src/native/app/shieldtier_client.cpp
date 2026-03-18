#include "app/shieldtier_client.h"

#include <chrono>
#include <ctime>

#include "include/cef_app.h"
#include "browser/navigation.h"
#include "ipc/ipc_protocol.h"

#if defined(OS_MAC) || defined(OS_MACOS)
#include "app/app_mac.h"
#endif

ShieldTierClient::ShieldTierClient(const std::string& root_cache_path)
    : request_handler_(new shieldtier::RequestHandler()),
      download_handler_(new shieldtier::DownloadHandler()),
      session_manager_(std::make_unique<shieldtier::SessionManager>(
          root_cache_path)) {
    CefMessageRouterConfig config;
    message_router_ = CefMessageRouterBrowserSide::Create(config);
    message_handler_ = std::make_unique<shieldtier::MessageHandler>(
        session_manager_.get());
    message_router_->AddHandler(message_handler_.get(), false);
    request_handler_->set_message_router(message_router_);
    event_bridge_ = std::make_unique<shieldtier::EventBridge>();
    message_handler_->set_event_bridge(event_bridge_.get());
    request_handler_->set_event_bridge(event_bridge_.get());
    request_handler_->set_session_manager(session_manager_.get());
    request_handler_->set_message_handler(message_handler_.get());
    request_handler_->set_capture_manager(message_handler_->capture_manager());
    request_handler_->set_threat_feed_manager(message_handler_->threat_feed_manager());
    request_handler_->set_content_analyzer(message_handler_->content_analyzer());
    message_handler_->set_ui_client(this);
}

void ShieldTierClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
    fprintf(stderr, "[ShieldTier] OnAfterCreated: browser_id=%d\n",
            browser->GetIdentifier());
    browser_ = browser;
    browser_count_++;
    session_manager_->on_browser_created(browser);
    event_bridge_->set_browser(browser);
    request_handler_->set_ui_browser_id(browser->GetIdentifier());
}

bool ShieldTierClient::DoClose(CefRefPtr<CefBrowser> /*browser*/) {
    return false;
}

void ShieldTierClient::OnBeforeClose(CefRefPtr<CefBrowser> browser) {
    message_router_->OnBeforeClose(browser);
    session_manager_->on_browser_closed(browser);
    event_bridge_->clear_browser();

    if (browser_ && browser_->IsSame(browser)) {
        // UI browser closing — also close content browser
        if (content_client_ && content_client_->browser()) {
            content_client_->browser()->GetHost()->CloseBrowser(true);
        }
        browser_ = nullptr;
    }
    browser_count_--;
    if (browser_count_ <= 0) {
        CefQuitMessageLoop();
    }
}

void ShieldTierClient::OnBeforeContextMenu(
        CefRefPtr<CefBrowser> /*browser*/,
        CefRefPtr<CefFrame> /*frame*/,
        CefRefPtr<CefContextMenuParams> /*params*/,
        CefRefPtr<CefMenuModel> model) {
    // The UI browser renders our React app — suppress all browser context menus
    // (no "View Page Source", "Back", "Forward", etc.)
    model->Clear();
}

void ShieldTierClient::OnTitleChange(CefRefPtr<CefBrowser> /*browser*/,
                                     const CefString& /*title*/) {}

void ShieldTierClient::OnLoadingStateChange(CefRefPtr<CefBrowser> browser,
                                             bool is_loading, bool can_go_back,
                                             bool can_go_forward) {
    // UI browser always shows shieldtier://app/ — nav state comes from content browser
    std::string url;
    auto frame = browser->GetMainFrame();
    if (frame) {
        url = frame->GetURL().ToString();
    }
    fprintf(stderr, "[ShieldTier] UI OnLoadingStateChange: loading=%d url=%s\n",
            is_loading, url.c_str());
}

void ShieldTierClient::OnLoadError(CefRefPtr<CefBrowser> /*browser*/,
                                    CefRefPtr<CefFrame> /*frame*/,
                                    ErrorCode errorCode,
                                    const CefString& errorText,
                                    const CefString& failedUrl) {
    fprintf(stderr, "[ShieldTier] OnLoadError: code=%d text=%s url=%s\n",
            errorCode, errorText.ToString().c_str(),
            failedUrl.ToString().c_str());
}

bool ShieldTierClient::OnProcessMessageReceived(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefProcessId source_process,
        CefRefPtr<CefProcessMessage> message) {
    return message_router_->OnProcessMessageReceived(
        browser, frame, source_process, message);
}

void ShieldTierClient::create_content_browser() {
    if (content_client_) return;

#if defined(OS_MAC) || defined(OS_MACOS)
    void* parent_view = shieldtier_mac_get_content_view();
    if (!parent_view) {
        fprintf(stderr, "[ShieldTier] create_content_browser: no parent view\n");
        return;
    }

    // Create an NSView to host the content browser
    // We use Objective-C runtime from C++ via the extern "C" helpers
    // Actually we can create the view using Cocoa from the .mm helpers — but
    // for simplicity we'll create it inline via the ObjC bridging in app_mac
    // For now, we'll set the content browser as a child of the main content view
    // with initial 1x1 size (will be resized by set_content_bounds)

    std::string pending_url = pending_content_url_;
    pending_content_url_.clear();

    content_client_ = new ContentBrowserClient(
        request_handler_, download_handler_,
        event_bridge_.get(), session_manager_.get(),
        [this, pending_url]() {
            if (content_client_ && content_client_->browser()) {
                auto host = content_client_->browser()->GetHost();
                void* view = host->GetWindowHandle();
                if (view) {
                    // Disable autoresizing — frame is managed by set_content_bounds
                    shieldtier_mac_set_view_fixed(view);

                    // Apply pending bounds if setBounds was called before browser was ready
                    if (has_pending_bounds_) {
                        shieldtier_mac_set_view_frame(view, pending_x_, pending_y_,
                                                       pending_w_, pending_h_);
                        host->WasResized();
                        has_pending_bounds_ = false;
                        fprintf(stderr, "[ShieldTier] Applied pending bounds: %dx%d+%d+%d\n",
                                pending_w_, pending_h_, pending_x_, pending_y_);
                    } else {
                        // No pending bounds yet — start hidden at 1x1 until React calls setBounds
                        shieldtier_mac_set_view_hidden(view, true);
                    }
                }
            }

            // Navigate to pending URL
            if (!pending_url.empty() && content_client_ && content_client_->browser()) {
                shieldtier::Navigation::load_url(content_client_->browser(), pending_url);
                show_content_browser();
            }
            enable_content_network_tracking();
        });

    CefWindowInfo window_info;
    window_info.runtime_style = CEF_RUNTIME_STYLE_ALLOY;
    window_info.SetAsChild(parent_view, CefRect(0, 0, 1, 1));

    CefBrowserSettings browser_settings;
    browser_settings.default_font_size = 14;
    browser_settings.minimum_font_size = 9;
    CefRefPtr<CefRequestContext> context =
        CefRequestContext::GetGlobalContext();

    CefBrowserHost::CreateBrowser(window_info, content_client_,
                                   "about:blank", browser_settings,
                                   nullptr, context);
    fprintf(stderr, "[ShieldTier] Content browser creation initiated\n");
#endif
}

void ShieldTierClient::set_content_bounds(int x, int y, int w, int h) {
#if defined(OS_MAC) || defined(OS_MACOS)
    // Store bounds — if browser isn't ready yet, apply them in the on-ready callback
    pending_x_ = x;
    pending_y_ = y;
    pending_w_ = w;
    pending_h_ = h;
    has_pending_bounds_ = true;

    if (!content_client_ || !content_client_->browser()) return;

    auto host = content_client_->browser()->GetHost();
    void* view = host->GetWindowHandle();
    if (view) {
        shieldtier_mac_set_view_frame(view, x, y, w, h);
        shieldtier_mac_set_view_hidden(view, false);
        host->NotifyMoveOrResizeStarted();
        host->WasResized();
        has_pending_bounds_ = false;
    }
#endif
}

void ShieldTierClient::show_content_browser() {
#if defined(OS_MAC) || defined(OS_MACOS)
    if (!content_client_ || !content_client_->browser()) return;

    auto host = content_client_->browser()->GetHost();
    void* view = host->GetWindowHandle();
    if (view) shieldtier_mac_set_view_hidden(view, false);
#endif
}

void ShieldTierClient::hide_content_browser() {
#if defined(OS_MAC) || defined(OS_MACOS)
    if (!content_client_ || !content_client_->browser()) return;

    auto host = content_client_->browser()->GetHost();
    void* view = host->GetWindowHandle();
    if (view) shieldtier_mac_set_view_hidden(view, true);
#endif
}

void ShieldTierClient::navigate_content(const std::string& url) {
    if (content_client_ && content_client_->browser()) {
        shieldtier::Navigation::load_url(content_client_->browser(), url);
        show_content_browser();
    } else {
        pending_content_url_ = url;
        create_content_browser();
    }
}

void ShieldTierClient::content_go_back() {
    if (content_client_ && content_client_->browser()) {
        shieldtier::Navigation::go_back(content_client_->browser());
    }
}

void ShieldTierClient::content_go_forward() {
    if (content_client_ && content_client_->browser()) {
        shieldtier::Navigation::go_forward(content_client_->browser());
    }
}

void ShieldTierClient::content_reload() {
    if (content_client_ && content_client_->browser()) {
        shieldtier::Navigation::reload(content_client_->browser());
    }
}

void ShieldTierClient::content_stop() {
    if (content_client_ && content_client_->browser()) {
        shieldtier::Navigation::stop(content_client_->browser());
    }
}

void ShieldTierClient::content_set_zoom(double factor) {
    if (content_client_ && content_client_->browser()) {
        shieldtier::Navigation::set_zoom_level(content_client_->browser(), factor);
    }
}

double ShieldTierClient::content_get_zoom() const {
    if (content_client_ && content_client_->browser()) {
        return shieldtier::Navigation::get_zoom_level(content_client_->browser());
    }
    return 0.0;
}

CefRefPtr<CefBrowser> ShieldTierClient::content_browser() const {
    if (content_client_) return content_client_->browser();
    return nullptr;
}

// --- DevToolsObserver implementation ---

int ShieldTierClient::DevToolsObserver::send(
        CefRefPtr<CefBrowserHost> host, const std::string& method,
        const shieldtier::json& params, ResultCallback cb) {
    int id = next_id_++;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_[id] = std::move(cb);
    }
    shieldtier::json msg = {{"id", id}, {"method", method}, {"params", params}};
    std::string s = msg.dump();
    host->SendDevToolsMessage(s.data(), s.size());
    return id;
}

void ShieldTierClient::DevToolsObserver::OnDevToolsMethodResult(
        CefRefPtr<CefBrowser> /*browser*/, int message_id, bool success,
        const void* result, size_t result_size) {
    ResultCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = callbacks_.find(message_id);
        if (it == callbacks_.end()) return;
        cb = std::move(it->second);
        callbacks_.erase(it);
    }
    std::string data(static_cast<const char*>(result), result_size);
    cb(success, data);
}

void ShieldTierClient::DevToolsObserver::OnDevToolsEvent(
    CefRefPtr<CefBrowser> /*browser*/,
    const CefString& method,
    const void* params,
    size_t params_size) {
    if (event_cb_) {
        std::string m = method.ToString();
        std::string p(static_cast<const char*>(params), params_size);
        event_cb_(m, p);
    }
}

void ShieldTierClient::ensure_devtools_observer() {
    if (devtools_observer_) return;
    if (!content_client_ || !content_client_->browser()) return;
    devtools_observer_ = new DevToolsObserver();
    devtools_registration_ =
        content_client_->browser()->GetHost()->AddDevToolsMessageObserver(
            devtools_observer_);
}

void ShieldTierClient::enable_content_network_tracking() {
    using json = shieldtier::json;
    ensure_devtools_observer();
    if (!devtools_observer_ || !content_client_ || !content_client_->browser())
        return;

    auto host = content_client_->browser()->GetHost();
    if (!host) return;

    // Set up event callback to capture Network.responseReceived
    auto* bridge = event_bridge_.get();
    devtools_observer_->set_event_callback(
        [bridge](const std::string& method, const std::string& params) {
            if (method != "Network.responseReceived") return;
            try {
                auto parsed = json::parse(params);
                auto& response = parsed["response"];
                std::string remote_ip = response.value("remoteIPAddress", "");
                if (remote_ip.empty()) return;

                // Strip IPv6 brackets if present
                if (!remote_ip.empty() && remote_ip.front() == '[') {
                    auto pos = remote_ip.find(']');
                    if (pos != std::string::npos)
                        remote_ip = remote_ip.substr(1, pos - 1);
                }

                std::string url = response.value("url", "");
                int remote_port = response.value("remotePort", 0);

                if (bridge) {
                    bridge->push("server_ip", {
                        {"ip", remote_ip},
                        {"port", remote_port},
                        {"url", url}
                    });
                }
            } catch (...) {}
        });

    // Enable Network domain to receive events
    devtools_observer_->send(host, "Network.enable", json::object(),
        [](bool /*success*/, const std::string& /*data*/) {});
}

// --- Screenshot via CDP Page.captureScreenshot ---

void ShieldTierClient::content_take_screenshot(CaptureCallback cb) {
    using json = shieldtier::json;
    if (!content_client_ || !content_client_->browser()) {
        if (cb) cb(json::object());
        return;
    }

    ensure_devtools_observer();
    auto host = content_client_->browser()->GetHost();
    if (!host || !devtools_observer_) {
        if (cb) cb(json::object());
        return;
    }

    auto frame = content_client_->browser()->GetMainFrame();
    std::string page_url = frame ? frame->GetURL().ToString() : "";

    devtools_observer_->send(host, "Page.captureScreenshot",
        json{{"format", "png"}},
        [cb, page_url](bool success, const std::string& data) {
            if (!success || data.empty()) {
                if (cb) cb(json::object());
                return;
            }
            try {
                auto parsed = json::parse(data);
                std::string b64 = parsed.value("data", "");
                if (b64.empty()) {
                    if (cb) cb(json::object());
                    return;
                }
                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                json result = {
                    {"id", "ss_" + std::to_string(now_ms)},
                    {"timestamp", now_ms},
                    {"dataUrl", "data:image/png;base64," + b64},
                    {"url", page_url},
                    {"title", "Screenshot"}
                };
                if (cb) cb(result);
            } catch (...) {
                if (cb) cb(json::object());
            }
        });
}

std::string ShieldTierClient::open_file_dialog(const std::string& title,
                                                const std::string& file_types) {
#if defined(OS_MAC) || defined(OS_MACOS)
    char* path = shieldtier_mac_open_file_dialog(title.c_str(), file_types.c_str());
    if (path) {
        std::string result(path);
        shieldtier_mac_free_string(path);
        return result;
    }
#endif
    return "";
}

std::string ShieldTierClient::save_file_dialog(const std::string& title,
                                                const std::string& default_name,
                                                const std::string& extension) {
#if defined(OS_MAC) || defined(OS_MACOS)
    char* path = shieldtier_mac_save_file_dialog(
        title.c_str(), default_name.c_str(), extension.c_str());
    if (path) {
        std::string result(path);
        shieldtier_mac_free_string(path);
        return result;
    }
#endif
    return "";
}

// --- DOM Snapshot via CDP Runtime.evaluate ---

void ShieldTierClient::content_take_dom_snapshot(CaptureCallback cb) {
    using json = shieldtier::json;
    if (!content_client_ || !content_client_->browser()) {
        if (cb) cb(json::object());
        return;
    }

    ensure_devtools_observer();
    auto host = content_client_->browser()->GetHost();
    if (!host || !devtools_observer_) {
        if (cb) cb(json::object());
        return;
    }

    auto frame = content_client_->browser()->GetMainFrame();
    std::string page_url = frame ? frame->GetURL().ToString() : "";

    devtools_observer_->send(host, "Runtime.evaluate",
        json{{"expression", "document.documentElement.outerHTML"},
             {"returnByValue", true}},
        [cb, page_url](bool success, const std::string& data) {
            if (!success || data.empty()) {
                if (cb) cb(json::object());
                return;
            }
            try {
                auto parsed = json::parse(data);
                std::string html = parsed["result"]["value"].get<std::string>();
                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                json result = {
                    {"id", "dom_" + std::to_string(now_ms)},
                    {"timestamp", now_ms},
                    {"html", html},
                    {"url", page_url},
                    {"title", "DOM Snapshot"}
                };
                if (cb) cb(result);
            } catch (...) {
                if (cb) cb(json::object());
            }
        });
}
