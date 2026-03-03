#pragma once

#include <memory>
#include <string>

#include "include/cef_client.h"
#include "include/cef_display_handler.h"
#include "include/cef_life_span_handler.h"

#include "browser/request_handler.h"
#include "browser/download_handler.h"
#include "browser/session_manager.h"

class ShieldTierClient : public CefClient,
                         public CefLifeSpanHandler,
                         public CefDisplayHandler {
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

    // CefLifeSpanHandler
    void OnAfterCreated(CefRefPtr<CefBrowser> browser) override;
    bool DoClose(CefRefPtr<CefBrowser> browser) override;
    void OnBeforeClose(CefRefPtr<CefBrowser> browser) override;

    // CefDisplayHandler
    void OnTitleChange(CefRefPtr<CefBrowser> browser,
                       const CefString& title) override;

    shieldtier::SessionManager* session_manager() {
        return session_manager_.get();
    }

private:
    CefRefPtr<shieldtier::RequestHandler> request_handler_;
    CefRefPtr<shieldtier::DownloadHandler> download_handler_;
    std::unique_ptr<shieldtier::SessionManager> session_manager_;

    CefRefPtr<CefBrowser> browser_;
    int browser_count_ = 0;

    IMPLEMENT_REFCOUNTING(ShieldTierClient);
    DISALLOW_COPY_AND_ASSIGN(ShieldTierClient);
};
