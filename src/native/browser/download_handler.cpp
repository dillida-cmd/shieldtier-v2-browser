#include "browser/download_handler.h"

#include <iostream>
#include <string>

namespace shieldtier {

bool DownloadHandler::CanDownload(CefRefPtr<CefBrowser> /*browser*/,
                                  const CefString& url,
                                  const CefString& /*request_method*/) {
    // Allow the download flow so CefResponseFilter can capture bytes.
    // The actual disk write is suppressed in OnBeforeDownload.
    std::cerr << "[download] permitted flow: " << url.ToString() << "\n";
    return true;
}

bool DownloadHandler::OnBeforeDownload(
    CefRefPtr<CefBrowser> /*browser*/,
    CefRefPtr<CefDownloadItem> download_item,
    const CefString& suggested_name,
    CefRefPtr<CefBeforeDownloadCallback> /*callback*/) {
    // Never call callback->Continue() — this suppresses the save dialog
    // and prevents any bytes from being written to disk.
    std::cerr << "[download] suppressed disk write: "
              << download_item->GetURL().ToString()
              << " -> " << suggested_name.ToString() << "\n";
    return true;
}

void DownloadHandler::OnDownloadUpdated(
    CefRefPtr<CefBrowser> /*browser*/,
    CefRefPtr<CefDownloadItem> download_item,
    CefRefPtr<CefDownloadItemCallback> /*callback*/) {
    // Don't cancel — response filter captures bytes in parallel.
    // Without calling callback->Continue() in OnBeforeDownload, no disk
    // write happens. The download may appear in CEF's internal state but
    // no file is created.
    if (download_item->IsComplete()) {
        std::cerr << "[download] completed (in-memory): "
                  << download_item->GetURL().ToString()
                  << " size=" << download_item->GetReceivedBytes() << "\n";
    }
}

}  // namespace shieldtier
