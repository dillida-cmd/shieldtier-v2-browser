#include "app/shieldtier_client.h"

#include "include/cef_app.h"

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
}

void ShieldTierClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
    browser_ = browser;
    browser_count_++;
    session_manager_->on_browser_created(browser);
    event_bridge_->set_browser(browser);
}

bool ShieldTierClient::DoClose(CefRefPtr<CefBrowser> /*browser*/) {
    return false;
}

void ShieldTierClient::OnBeforeClose(CefRefPtr<CefBrowser> browser) {
    message_router_->OnBeforeClose(browser);
    session_manager_->on_browser_closed(browser);
    event_bridge_->clear_browser();

    if (browser_ && browser_->IsSame(browser)) {
        browser_ = nullptr;
    }
    browser_count_--;
    if (browser_count_ <= 0) {
        CefQuitMessageLoop();
    }
}

void ShieldTierClient::OnTitleChange(CefRefPtr<CefBrowser> /*browser*/,
                                     const CefString& /*title*/) {}

void ShieldTierClient::OnLoadingStateChange(CefRefPtr<CefBrowser> browser,
                                             bool is_loading, bool can_go_back,
                                             bool can_go_forward) {
    std::string url;
    auto frame = browser->GetMainFrame();
    if (frame) {
        url = frame->GetURL().ToString();
    }
    event_bridge_->push_navigation_state(
        can_go_back, can_go_forward, is_loading, url, "");
}

bool ShieldTierClient::OnProcessMessageReceived(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefProcessId source_process,
        CefRefPtr<CefProcessMessage> message) {
    return message_router_->OnProcessMessageReceived(
        browser, frame, source_process, message);
}
