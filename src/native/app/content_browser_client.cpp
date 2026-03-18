#include "app/content_browser_client.h"

#include "browser/navigation.h"

namespace {

// Custom context menu command IDs (must be > MENU_ID_USER_FIRST = 26500)
enum ContentMenuIds {
    kMenuCopyLink = 26501,
    kMenuCopyText = 26502,
    kMenuCopyImage = 26503,
    kMenuReload = 26504,
    kMenuBack = 26505,
    kMenuForward = 26506,
    kMenuViewSource = 26507,
    kMenuCopyPageUrl = 26508,
};

}  // namespace

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

// ═══════════════════════════════════════════════════════
// Context Menu for Content Browser (sandboxed websites)
// ═══════════════════════════════════════════════════════

void ContentBrowserClient::OnBeforeContextMenu(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> /*frame*/,
        CefRefPtr<CefContextMenuParams> params,
        CefRefPtr<CefMenuModel> model) {
    // Clear the default CEF menu and build our own
    model->Clear();

    auto type_flags = params->GetTypeFlags();

    // Link context
    if (type_flags & CM_TYPEFLAG_LINK) {
        model->AddItem(kMenuCopyLink, "Copy Link Address");
    }

    // Selection context
    if (type_flags & CM_TYPEFLAG_SELECTION) {
        model->AddItem(kMenuCopyText, "Copy Selected Text");
    }

    // Image context
    if (type_flags & CM_TYPEFLAG_MEDIA &&
        params->GetMediaType() == CM_MEDIATYPE_IMAGE) {
        model->AddItem(kMenuCopyImage, "Copy Image URL");
    }

    // Separator before navigation
    if (model->GetCount() > 0) {
        model->AddSeparator();
    }

    // Navigation
    if (browser->CanGoBack()) {
        model->AddItem(kMenuBack, "Back");
    }
    if (browser->CanGoForward()) {
        model->AddItem(kMenuForward, "Forward");
    }
    model->AddItem(kMenuReload, "Reload");

    model->AddSeparator();

    // Page info
    model->AddItem(kMenuCopyPageUrl, "Copy Page URL");
    model->AddItem(kMenuViewSource, "View Page Source");
}

bool ContentBrowserClient::OnContextMenuCommand(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefRefPtr<CefContextMenuParams> params,
        int command_id, EventFlags /*event_flags*/) {
    switch (command_id) {
        case kMenuCopyLink: {
            CefString link = params->GetLinkUrl();
            if (!link.empty() && frame) {
                frame->ExecuteJavaScript(
                    "navigator.clipboard.writeText('" +
                    link.ToString() + "');",
                    frame->GetURL(), 0);
            }
            return true;
        }
        case kMenuCopyText: {
            CefString text = params->GetSelectionText();
            if (!text.empty() && frame) {
                // Escape single quotes in selection
                std::string escaped = text.ToString();
                size_t pos = 0;
                while ((pos = escaped.find('\'', pos)) != std::string::npos) {
                    escaped.replace(pos, 1, "\\'");
                    pos += 2;
                }
                frame->ExecuteJavaScript(
                    "navigator.clipboard.writeText('" + escaped + "');",
                    frame->GetURL(), 0);
            }
            return true;
        }
        case kMenuCopyImage: {
            CefString src = params->GetSourceUrl();
            if (!src.empty() && frame) {
                frame->ExecuteJavaScript(
                    "navigator.clipboard.writeText('" +
                    src.ToString() + "');",
                    frame->GetURL(), 0);
            }
            return true;
        }
        case kMenuReload:
            browser->Reload();
            return true;
        case kMenuBack:
            browser->GoBack();
            return true;
        case kMenuForward:
            browser->GoForward();
            return true;
        case kMenuCopyPageUrl: {
            if (frame) {
                CefString url = frame->GetURL();
                frame->ExecuteJavaScript(
                    "navigator.clipboard.writeText('" +
                    url.ToString() + "');",
                    url, 0);
            }
            return true;
        }
        case kMenuViewSource: {
            if (frame) {
                frame->ViewSource();
            }
            return true;
        }
        default:
            return false;
    }
}
