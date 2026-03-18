#pragma once

#include <functional>
#include <string>

#include "include/cef_client.h"
#include "include/cef_context_menu_handler.h"
#include "include/cef_display_handler.h"
#include "include/cef_life_span_handler.h"
#include "include/cef_load_handler.h"

#include "browser/request_handler.h"
#include "browser/download_handler.h"
#include "browser/session_manager.h"
#include "ipc/event_bridge.h"

class ContentBrowserClient : public CefClient,
                             public CefContextMenuHandler,
                             public CefLifeSpanHandler,
                             public CefDisplayHandler,
                             public CefLoadHandler {
public:
    using ReadyCallback = std::function<void()>;

    ContentBrowserClient(CefRefPtr<shieldtier::RequestHandler> request_handler,
                         CefRefPtr<shieldtier::DownloadHandler> download_handler,
                         shieldtier::EventBridge* event_bridge,
                         shieldtier::SessionManager* session_manager,
                         ReadyCallback on_ready);

    CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override { return this; }
    CefRefPtr<CefDisplayHandler> GetDisplayHandler() override { return this; }
    CefRefPtr<CefRequestHandler> GetRequestHandler() override { return request_handler_; }
    CefRefPtr<CefDownloadHandler> GetDownloadHandler() override { return download_handler_; }
    CefRefPtr<CefLoadHandler> GetLoadHandler() override { return this; }
    CefRefPtr<CefContextMenuHandler> GetContextMenuHandler() override { return this; }

    // CefContextMenuHandler — context menu for the sandboxed content browser
    void OnBeforeContextMenu(CefRefPtr<CefBrowser> browser,
                             CefRefPtr<CefFrame> frame,
                             CefRefPtr<CefContextMenuParams> params,
                             CefRefPtr<CefMenuModel> model) override;
    bool OnContextMenuCommand(CefRefPtr<CefBrowser> browser,
                              CefRefPtr<CefFrame> frame,
                              CefRefPtr<CefContextMenuParams> params,
                              int command_id, EventFlags event_flags) override;

    // CefLifeSpanHandler
    bool OnBeforePopup(CefRefPtr<CefBrowser> browser,
                       CefRefPtr<CefFrame> frame,
                       int popup_id,
                       const CefString& target_url,
                       const CefString& target_frame_name,
                       CefLifeSpanHandler::WindowOpenDisposition target_disposition,
                       bool user_gesture,
                       const CefPopupFeatures& popupFeatures,
                       CefWindowInfo& windowInfo,
                       CefRefPtr<CefClient>& client,
                       CefBrowserSettings& settings,
                       CefRefPtr<CefDictionaryValue>& extra_info,
                       bool* no_javascript_access) override;
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

    CefRefPtr<CefBrowser> browser() const { return browser_; }

private:
    CefRefPtr<shieldtier::RequestHandler> request_handler_;
    CefRefPtr<shieldtier::DownloadHandler> download_handler_;
    shieldtier::EventBridge* event_bridge_;
    shieldtier::SessionManager* session_manager_;
    ReadyCallback on_ready_;

    CefRefPtr<CefBrowser> browser_;

    IMPLEMENT_REFCOUNTING(ContentBrowserClient);
    DISALLOW_COPY_AND_ASSIGN(ContentBrowserClient);
};
