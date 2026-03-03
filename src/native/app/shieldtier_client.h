#pragma once

#include "include/cef_client.h"
#include "include/cef_display_handler.h"
#include "include/cef_life_span_handler.h"

class ShieldTierClient : public CefClient,
                         public CefLifeSpanHandler,
                         public CefDisplayHandler {
public:
    ShieldTierClient() = default;

    CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override {
        return this;
    }

    CefRefPtr<CefDisplayHandler> GetDisplayHandler() override {
        return this;
    }

    // CefLifeSpanHandler
    void OnAfterCreated(CefRefPtr<CefBrowser> browser) override;
    bool DoClose(CefRefPtr<CefBrowser> browser) override;
    void OnBeforeClose(CefRefPtr<CefBrowser> browser) override;

    // CefDisplayHandler
    void OnTitleChange(CefRefPtr<CefBrowser> browser,
                       const CefString& title) override;

private:
    CefRefPtr<CefBrowser> browser_;
    int browser_count_ = 0;

    IMPLEMENT_REFCOUNTING(ShieldTierClient);
    DISALLOW_COPY_AND_ASSIGN(ShieldTierClient);
};
