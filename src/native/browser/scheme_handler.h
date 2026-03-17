#pragma once

#include <string>
#include <vector>

#include "include/cef_resource_handler.h"
#include "include/cef_scheme.h"

namespace shieldtier {

class SchemeHandler : public CefResourceHandler {
public:
    SchemeHandler(const std::string& root_dir, const std::string& shim_dir);

    bool Open(CefRefPtr<CefRequest> request, bool& handle_request,
              CefRefPtr<CefCallback> callback) override;

    void GetResponseHeaders(CefRefPtr<CefResponse> response,
                            int64_t& response_length,
                            CefString& redirect_url) override;

    bool Read(void* data_out, int bytes_to_read, int& bytes_read,
              CefRefPtr<CefResourceReadCallback> callback) override;

    void Cancel() override;

private:
    static std::string get_mime_type(const std::string& extension);

    std::string root_dir_;
    std::string shim_dir_;
    std::vector<uint8_t> data_;
    size_t offset_ = 0;
    std::string mime_type_ = "text/html";
    int status_code_ = 200;

    IMPLEMENT_REFCOUNTING(SchemeHandler);
    DISALLOW_COPY_AND_ASSIGN(SchemeHandler);
};

class SchemeHandlerFactory : public CefSchemeHandlerFactory {
public:
    SchemeHandlerFactory(const std::string& root_dir, const std::string& shim_dir);

    CefRefPtr<CefResourceHandler> Create(
        CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
        const CefString& scheme_name,
        CefRefPtr<CefRequest> request) override;

private:
    std::string root_dir_;
    std::string shim_dir_;

    IMPLEMENT_REFCOUNTING(SchemeHandlerFactory);
    DISALLOW_COPY_AND_ASSIGN(SchemeHandlerFactory);
};

}  // namespace shieldtier
