#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "include/cef_client.h"
#include "include/cef_context_menu_handler.h"
#include "include/cef_display_handler.h"
#include "include/cef_life_span_handler.h"
#include "include/wrapper/cef_message_router.h"

#include "app/content_browser_client.h"
#include "browser/request_handler.h"
#include "browser/download_handler.h"
#include "browser/session_manager.h"
#include "common/json.h"
#include "ipc/event_bridge.h"
#include "ipc/message_handler.h"

class ShieldTierClient : public CefClient,
                         public CefContextMenuHandler,
                         public CefLifeSpanHandler,
                         public CefDisplayHandler,
                         public CefLoadHandler {
public:
    explicit ShieldTierClient(const std::string& root_cache_path);

    CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override {
        return this;
    }

    CefRefPtr<CefDisplayHandler> GetDisplayHandler() override {
        return this;
    }

    CefRefPtr<CefRequestHandler> GetRequestHandler() override {
        return request_handler_;
    }

    CefRefPtr<CefDownloadHandler> GetDownloadHandler() override {
        return download_handler_;
    }

    CefRefPtr<CefLoadHandler> GetLoadHandler() override { return this; }

    CefRefPtr<CefContextMenuHandler> GetContextMenuHandler() override {
        return this;
    }

    // CefContextMenuHandler — suppress browser context menus in the UI browser
    void OnBeforeContextMenu(CefRefPtr<CefBrowser> browser,
                             CefRefPtr<CefFrame> frame,
                             CefRefPtr<CefContextMenuParams> params,
                             CefRefPtr<CefMenuModel> model) override;

    // CefLifeSpanHandler
    void OnAfterCreated(CefRefPtr<CefBrowser> browser) override;
    bool DoClose(CefRefPtr<CefBrowser> browser) override;
    void OnBeforeClose(CefRefPtr<CefBrowser> browser) override;

    // CefDisplayHandler
    void OnTitleChange(CefRefPtr<CefBrowser> browser,
                       const CefString& title) override;

    // CefLoadHandler
    void OnLoadingStateChange(CefRefPtr<CefBrowser> browser, bool is_loading,
                              bool can_go_back, bool can_go_forward) override;
    void OnLoadError(CefRefPtr<CefBrowser> browser,
                     CefRefPtr<CefFrame> frame,
                     ErrorCode errorCode,
                     const CefString& errorText,
                     const CefString& failedUrl) override;

    // CefClient
    bool OnProcessMessageReceived(CefRefPtr<CefBrowser> browser,
                                  CefRefPtr<CefFrame> frame,
                                  CefProcessId source_process,
                                  CefRefPtr<CefProcessMessage> message) override;

    shieldtier::SessionManager* session_manager() {
        return session_manager_.get();
    }

    shieldtier::EventBridge* event_bridge() { return event_bridge_.get(); }

    void create_content_browser();
    void set_content_bounds(int x, int y, int w, int h);
    void show_content_browser();
    void hide_content_browser();
    void navigate_content(const std::string& url);
    void content_go_back();
    void content_go_forward();
    void content_reload();
    void content_stop();
    void content_set_zoom(double factor);
    double content_get_zoom() const;
    CefRefPtr<CefBrowser> content_browser() const;

    using CaptureCallback = std::function<void(const shieldtier::json& result)>;
    void content_take_screenshot(CaptureCallback cb);
    void content_take_dom_snapshot(CaptureCallback cb);
    void enable_content_network_tracking();
    std::string open_file_dialog(const std::string& title, const std::string& file_types);
    std::string save_file_dialog(const std::string& title, const std::string& default_name, const std::string& extension);

private:
    // DevTools CDP observer for content browser (screenshot, DOM capture, network)
    class DevToolsObserver : public CefDevToolsMessageObserver {
    public:
        using ResultCallback = std::function<void(bool success, const std::string& data)>;
        using EventCallback = std::function<void(const std::string& method, const std::string& params)>;

        int send(CefRefPtr<CefBrowserHost> host, const std::string& method,
                 const shieldtier::json& params, ResultCallback cb);

        void OnDevToolsMethodResult(CefRefPtr<CefBrowser> browser,
                                    int message_id, bool success,
                                    const void* result,
                                    size_t result_size) override;

        void OnDevToolsEvent(CefRefPtr<CefBrowser> browser,
                             const CefString& method,
                             const void* params,
                             size_t params_size) override;

        void set_event_callback(EventCallback cb) { event_cb_ = std::move(cb); }

    private:
        std::atomic<int> next_id_{1};
        std::mutex mutex_;
        std::unordered_map<int, ResultCallback> callbacks_;
        EventCallback event_cb_;
        IMPLEMENT_REFCOUNTING(DevToolsObserver);
    };

    void ensure_devtools_observer();
    CefRefPtr<DevToolsObserver> devtools_observer_;
    CefRefPtr<CefRegistration> devtools_registration_;
    CefRefPtr<shieldtier::RequestHandler> request_handler_;
    CefRefPtr<shieldtier::DownloadHandler> download_handler_;
    std::unique_ptr<shieldtier::SessionManager> session_manager_;
    CefRefPtr<CefMessageRouterBrowserSide> message_router_;
    std::unique_ptr<shieldtier::EventBridge> event_bridge_;
    std::unique_ptr<shieldtier::MessageHandler> message_handler_;

    CefRefPtr<CefBrowser> browser_;
    int browser_count_ = 0;

    CefRefPtr<ContentBrowserClient> content_client_;
    void* content_parent_view_ = nullptr;
    std::string pending_content_url_;

    // Pending bounds — stored when setBounds is called before content browser is ready
    bool has_pending_bounds_ = false;
    int pending_x_ = 0, pending_y_ = 0, pending_w_ = 0, pending_h_ = 0;

    IMPLEMENT_REFCOUNTING(ShieldTierClient);
    DISALLOW_COPY_AND_ASSIGN(ShieldTierClient);
};
