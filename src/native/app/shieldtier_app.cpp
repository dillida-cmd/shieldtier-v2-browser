#include "app/shieldtier_app.h"
#include "app/shieldtier_client.h"

#include "include/cef_browser.h"
#include "include/cef_command_line.h"

void ShieldTierApp::OnContextInitialized() {
    CefWindowInfo window_info;

#if defined(OS_WIN)
    window_info.SetAsPopup(nullptr, "ShieldTier");
#elif defined(OS_LINUX)
    window_info.SetAsChild(0, CefRect(0, 0, 1280, 720));
#endif
    // macOS: default-constructed CefWindowInfo creates an NSView-backed window

    CefBrowserSettings browser_settings;

    CefRefPtr<ShieldTierClient> client(new ShieldTierClient());

    CefBrowserHost::CreateBrowser(window_info, client, "about:blank",
                                  browser_settings, nullptr, nullptr);
}
