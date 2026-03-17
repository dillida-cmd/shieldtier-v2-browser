#include "browser/scheme_handler.h"

#include "include/cef_parser.h"

#include <filesystem>
#include <fstream>

namespace shieldtier {

namespace fs = std::filesystem;

SchemeHandler::SchemeHandler(const std::string& root_dir, const std::string& shim_dir)
    : root_dir_(root_dir), shim_dir_(shim_dir) {}

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

    // Canonicalize and verify the resolved path is within root_dir_
    std::error_code ec;
    fs::path canonical_root = fs::weakly_canonical(root_dir_, ec);
    fs::path canonical_file = fs::weakly_canonical(file_path, ec);
    if (!canonical_file.string().starts_with(canonical_root.string())) {
        status_code_ = 403;
        return true;
    }

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

    // Inject preload shim into index.html — creates window.shieldtier API
    // that V1's React renderer expects, routing calls through cefQuery
    if (file_path.filename() == "index.html" && !shim_dir_.empty()) {
        fs::path shim_path = fs::path(shim_dir_) / "preload-shim.js";
        if (fs::exists(shim_path)) {
            std::ifstream shim_file(shim_path, std::ios::binary | std::ios::ate);
            if (shim_file.is_open()) {
                auto shim_size = shim_file.tellg();
                shim_file.seekg(0);
                std::string shim_content(static_cast<size_t>(shim_size), '\0');
                shim_file.read(shim_content.data(), shim_size);

                // Build a <script> tag to inject before </head>
                std::string inject = "<script>" + shim_content + "</script>";
                std::string html(data_.begin(), data_.end());

                // Also relax CSP to allow inline script (the shim)
                // Replace existing CSP meta tag to allow 'unsafe-inline'
                auto head_pos = html.find("</head>");
                if (head_pos != std::string::npos) {
                    html.insert(head_pos, inject);
                    data_.assign(html.begin(), html.end());
                    fprintf(stderr, "[ShieldTier] Injected preload shim (%zu bytes)\n",
                            shim_content.size());
                }
            }
        }
    }

    return true;
}

void SchemeHandler::GetResponseHeaders(CefRefPtr<CefResponse> response,
                                       int64_t& response_length,
                                       CefString&) {
    response->SetStatus(status_code_);
    response->SetMimeType(mime_type_);

    if (status_code_ == 200) {
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
    if (ext == ".js" || ext == ".mjs") return "application/javascript";
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

SchemeHandlerFactory::SchemeHandlerFactory(const std::string& root_dir,
                                             const std::string& shim_dir)
    : root_dir_(root_dir), shim_dir_(shim_dir) {}

CefRefPtr<CefResourceHandler> SchemeHandlerFactory::Create(
    CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>,
    const CefString&, CefRefPtr<CefRequest>) {
    return new SchemeHandler(root_dir_, shim_dir_);
}

}  // namespace shieldtier
