#pragma once

#include "include/cef_download_handler.h"

namespace shieldtier {

// Suppresses all disk writes. Downloads are captured in-memory by
// DownloadCaptureFilter; this handler ensures nothing reaches the filesystem.
class DownloadHandler : public CefDownloadHandler {
public:
    DownloadHandler() = default;

    bool CanDownload(CefRefPtr<CefBrowser> browser,
                     const CefString& url,
                     const CefString& request_method) override;

    bool OnBeforeDownload(CefRefPtr<CefBrowser> browser,
                          CefRefPtr<CefDownloadItem> download_item,
                          const CefString& suggested_name,
                          CefRefPtr<CefBeforeDownloadCallback> callback) override;

    void OnDownloadUpdated(CefRefPtr<CefBrowser> browser,
                           CefRefPtr<CefDownloadItem> download_item,
                           CefRefPtr<CefDownloadItemCallback> callback) override;

private:
    IMPLEMENT_REFCOUNTING(DownloadHandler);
    DISALLOW_COPY_AND_ASSIGN(DownloadHandler);
};

}  // namespace shieldtier
