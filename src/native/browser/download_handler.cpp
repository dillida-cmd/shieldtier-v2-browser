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
    CefRefPtr<CefDownloadItemCallback> callback) {
    // Safety net: cancel any download that somehow started writing to disk.
    if (download_item->IsInProgress()) {
        std::cerr << "[download] cancelling unexpected in-progress download: "
                  << download_item->GetURL().ToString() << "\n";
        callback->Cancel();
    }
}

}  // namespace shieldtier
