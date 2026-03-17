#include "app/content_browser_client.h"
#include "browser/navigation.h"

ContentBrowserClient::ContentBrowserClient(
        CefRefPtr<shieldtier::RequestHandler> request_handler,
        CefRefPtr<shieldtier::DownloadHandler> download_handler,
        shieldtier::EventBridge* event_bridge,
        shieldtier::SessionManager* session_manager,
        ReadyCallback on_ready)
    : request_handler_(request_handler),
      download_handler_(download_handler),
      event_bridge_(event_bridge),
      session_manager_(session_manager),
      on_ready_(std::move(on_ready)) {}

bool ContentBrowserClient::OnBeforePopup(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> /*frame*/,
        int /*popup_id*/,
        const CefString& target_url,
        const CefString& /*target_frame_name*/,
        CefLifeSpanHandler::WindowOpenDisposition /*target_disposition*/,
        bool /*user_gesture*/,
        const CefPopupFeatures& /*popupFeatures*/,
        CefWindowInfo& /*windowInfo*/,
        CefRefPtr<CefClient>& /*client*/,
        CefBrowserSettings& /*settings*/,
        CefRefPtr<CefDictionaryValue>& /*extra_info*/,
        bool* /*no_javascript_access*/) {
    // SOC browser: intercept popups (OAuth, phishing sign-ins, etc.)
    // and navigate the content browser inline instead of opening a new window.
    std::string url = target_url.ToString();
    fprintf(stderr, "[ContentBrowser] OnBeforePopup: intercepting popup → %s\n",
            url.c_str());

    if (!url.empty() && url != "about:blank") {
        // Navigate the current content browser to the popup URL
        shieldtier::Navigation::load_url(browser, url);
    }

    // Return true = cancel the popup (don't create a new window)
    return true;
}

void ContentBrowserClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
    fprintf(stderr, "[ContentBrowser] OnAfterCreated: browser_id=%d\n",
            browser->GetIdentifier());
    browser_ = browser;
    session_manager_->on_browser_created(browser);
    if (on_ready_) {
        on_ready_();
    }
}

bool ContentBrowserClient::DoClose(CefRefPtr<CefBrowser> /*browser*/) {
    return false;
}

void ContentBrowserClient::OnBeforeClose(CefRefPtr<CefBrowser> browser) {
    fprintf(stderr, "[ContentBrowser] OnBeforeClose: browser_id=%d\n",
            browser->GetIdentifier());
    session_manager_->on_browser_closed(browser);
    browser_ = nullptr;
}

void ContentBrowserClient::OnTitleChange(CefRefPtr<CefBrowser> browser,
                                          const CefString& title) {
    if (event_bridge_) {
        auto frame = browser->GetMainFrame();
        std::string url = frame ? frame->GetURL().ToString() : "";
        event_bridge_->push_navigation_state(
            browser->CanGoBack(), browser->CanGoForward(),
            browser->IsLoading(), url, title.ToString());
    }
}

void ContentBrowserClient::OnLoadingStateChange(CefRefPtr<CefBrowser> browser,
                                                  bool is_loading,
                                                  bool can_go_back,
                                                  bool can_go_forward) {
    std::string url;
    auto frame = browser->GetMainFrame();
    if (frame) {
        url = frame->GetURL().ToString();
    }
    fprintf(stderr, "[ContentBrowser] OnLoadingStateChange: loading=%d url=%s\n",
            is_loading, url.c_str());
    if (event_bridge_) {
        event_bridge_->push_navigation_state(
            can_go_back, can_go_forward, is_loading, url, "");
    }
}

void ContentBrowserClient::OnLoadError(CefRefPtr<CefBrowser> /*browser*/,
                                        CefRefPtr<CefFrame> frame,
                                        ErrorCode errorCode,
                                        const CefString& errorText,
                                        const CefString& failedUrl) {
    fprintf(stderr, "[ContentBrowser] OnLoadError: code=%d text=%s url=%s\n",
            errorCode, errorText.ToString().c_str(),
            failedUrl.ToString().c_str());

    // Only report main frame errors, ignore subframe/aborted
    if (!frame || !frame->IsMain()) return;
    if (errorCode == ERR_ABORTED) return;

    if (event_bridge_) {
        event_bridge_->push_load_error(
            static_cast<int>(errorCode),
            errorText.ToString(),
            failedUrl.ToString());
    }
}
