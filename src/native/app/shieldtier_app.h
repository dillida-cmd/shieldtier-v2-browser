#pragma once

#include "include/cef_app.h"
#include "include/cef_browser_process_handler.h"

class ShieldTierApp : public CefApp, public CefBrowserProcessHandler {
public:
    ShieldTierApp() = default;

    CefRefPtr<CefBrowserProcessHandler> GetBrowserProcessHandler() override {
        return this;
    }

    void OnContextInitialized() override;

private:
    IMPLEMENT_REFCOUNTING(ShieldTierApp);
    DISALLOW_COPY_AND_ASSIGN(ShieldTierApp);
};
