#include "browser/scheme_handler.h"

#include "include/cef_parser.h"

#include <filesystem>
#include <fstream>

namespace shieldtier {

namespace fs = std::filesystem;

SchemeHandler::SchemeHandler(const std::string& root_dir) : root_dir_(root_dir) {}

bool SchemeHandler::Open(CefRefPtr<CefRequest> request, bool& handle_request,
                         CefRefPtr<CefCallback>) {
    handle_request = true;

    CefURLParts url_parts;
    if (!CefParseURL(request->GetURL(), url_parts)) {
        status_code_ = 400;
        return true;
    }

    std::string path = CefString(&url_parts.path).ToString();
    if (path.empty() || path == "/") {
        path = "/index.html";
    }

    if (path.find("..") != std::string::npos) {
        status_code_ = 403;
        return true;
    }

    fs::path file_path = fs::path(root_dir_) / path.substr(1);

    if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
        file_path = fs::path(root_dir_) / "index.html";
        if (!fs::exists(file_path)) {
            status_code_ = 404;
            return true;
        }
    }

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        status_code_ = 500;
        return true;
    }

    auto size = file.tellg();
    file.seekg(0);
    data_.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(data_.data()), size);

    mime_type_ = get_mime_type(file_path.extension().string());
    status_code_ = 200;
    return true;
}

void SchemeHandler::GetResponseHeaders(CefRefPtr<CefResponse> response,
                                       int64_t& response_length,
                                       CefString&) {
    response->SetStatus(status_code_);
    response->SetMimeType(mime_type_);

    if (status_code_ == 200) {
        response->SetHeaderByName("Access-Control-Allow-Origin", "*", true);
        response_length = static_cast<int64_t>(data_.size());
    } else {
        response_length = 0;
    }
}

bool SchemeHandler::Read(void* data_out, int bytes_to_read, int& bytes_read,
                         CefRefPtr<CefResourceReadCallback>) {
    if (offset_ >= data_.size()) {
        bytes_read = 0;
        return false;
    }

    size_t remaining = data_.size() - offset_;
    size_t to_copy = std::min(static_cast<size_t>(bytes_to_read), remaining);
    memcpy(data_out, data_.data() + offset_, to_copy);
    offset_ += to_copy;
    bytes_read = static_cast<int>(to_copy);
    return true;
}

void SchemeHandler::Cancel() {
    data_.clear();
    offset_ = 0;
}

std::string SchemeHandler::get_mime_type(const std::string& ext) {
    if (ext == ".html") return "text/html";
    if (ext == ".js")   return "application/javascript";
    if (ext == ".css")  return "text/css";
    if (ext == ".json") return "application/json";
    if (ext == ".svg")  return "image/svg+xml";
    if (ext == ".png")  return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".woff")  return "font/woff";
    if (ext == ".woff2") return "font/woff2";
    if (ext == ".ttf")   return "font/ttf";
    if (ext == ".ico")   return "image/x-icon";
    if (ext == ".map")   return "application/json";
    return "application/octet-stream";
}

SchemeHandlerFactory::SchemeHandlerFactory(const std::string& root_dir)
    : root_dir_(root_dir) {}

CefRefPtr<CefResourceHandler> SchemeHandlerFactory::Create(
    CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>,
    const CefString&, CefRefPtr<CefRequest>) {
    return new SchemeHandler(root_dir_);
}

}  // namespace shieldtier
