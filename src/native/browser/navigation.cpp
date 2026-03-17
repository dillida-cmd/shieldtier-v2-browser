#include "browser/navigation.h"

#include "include/cef_frame.h"

namespace shieldtier {

void Navigation::go_back(CefRefPtr<CefBrowser> browser) {
    if (!browser)
        return;
    browser->GoBack();
}

void Navigation::go_forward(CefRefPtr<CefBrowser> browser) {
    if (!browser)
        return;
    browser->GoForward();
}

void Navigation::reload(CefRefPtr<CefBrowser> browser) {
    if (!browser)
        return;
    browser->Reload();
}

void Navigation::stop(CefRefPtr<CefBrowser> browser) {
    if (!browser)
        return;
    browser->StopLoad();
}

void Navigation::load_url(CefRefPtr<CefBrowser> browser,
                          const std::string& url) {
    if (!browser || url.empty())
        return;
    CefRefPtr<CefFrame> frame = browser->GetMainFrame();
    if (frame)
        frame->LoadURL(url);
}

std::string Navigation::get_url(CefRefPtr<CefBrowser> browser) {
    if (!browser)
        return {};
    CefRefPtr<CefFrame> frame = browser->GetMainFrame();
    if (!frame)
        return {};
    return frame->GetURL().ToString();
}

// Title is delivered asynchronously via CefDisplayHandler::OnTitleChange.
// No synchronous getter exists on CefBrowser.
std::string Navigation::get_title(CefRefPtr<CefBrowser> /*browser*/) {
    return {};
}

bool Navigation::can_go_back(CefRefPtr<CefBrowser> browser) {
    if (!browser)
        return false;
    return browser->CanGoBack();
}

bool Navigation::can_go_forward(CefRefPtr<CefBrowser> browser) {
    if (!browser)
        return false;
    return browser->CanGoForward();
}

bool Navigation::is_loading(CefRefPtr<CefBrowser> browser) {
    if (!browser)
        return false;
    return browser->IsLoading();
}

double Navigation::get_zoom_level(CefRefPtr<CefBrowser> browser) {
    if (!browser)
        return 0.0;
    CefRefPtr<CefBrowserHost> host = browser->GetHost();
    if (!host)
        return 0.0;
    return host->GetZoomLevel();
}

void Navigation::set_zoom_level(CefRefPtr<CefBrowser> browser, double level) {
    if (!browser)
        return;
    CefRefPtr<CefBrowserHost> host = browser->GetHost();
    if (host)
        host->SetZoomLevel(level);
}

}  // namespace shieldtier
