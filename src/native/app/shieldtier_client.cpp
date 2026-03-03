#include "app/shieldtier_client.h"

#include "include/cef_app.h"

void ShieldTierClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
    browser_ = browser;
    browser_count_++;
}

bool ShieldTierClient::DoClose(CefRefPtr<CefBrowser> /*browser*/) {
    return false;
}

void ShieldTierClient::OnBeforeClose(CefRefPtr<CefBrowser> /*browser*/) {
    browser_count_--;
    if (browser_count_ <= 0) {
        CefQuitMessageLoop();
    }
}

void ShieldTierClient::OnTitleChange(CefRefPtr<CefBrowser> /*browser*/,
                                     const CefString& /*title*/) {
    // Platform-specific title bar update will be added in a later phase
}
