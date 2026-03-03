#include "app/shieldtier_client.h"

#include "include/cef_app.h"

ShieldTierClient::ShieldTierClient(const std::string& root_cache_path)
    : request_handler_(new shieldtier::RequestHandler()),
      download_handler_(new shieldtier::DownloadHandler()),
      session_manager_(std::make_unique<shieldtier::SessionManager>(
          root_cache_path)) {}

void ShieldTierClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
    browser_ = browser;
    browser_count_++;
    session_manager_->on_browser_created(browser);
}

bool ShieldTierClient::DoClose(CefRefPtr<CefBrowser> /*browser*/) {
    return false;
}

void ShieldTierClient::OnBeforeClose(CefRefPtr<CefBrowser> browser) {
    session_manager_->on_browser_closed(browser);

    if (browser_ && browser_->IsSame(browser)) {
        browser_ = nullptr;
    }
    browser_count_--;
    if (browser_count_ <= 0) {
        CefQuitMessageLoop();
    }
}

void ShieldTierClient::OnTitleChange(CefRefPtr<CefBrowser> /*browser*/,
                                     const CefString& /*title*/) {
    // Platform-specific title bar update will be added in a later phase
}
