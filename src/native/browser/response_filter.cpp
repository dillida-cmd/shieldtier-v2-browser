#include "browser/response_filter.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>

#if defined(OS_MAC)
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/evp.h>
#endif

namespace shieldtier {

// ---------------------------------------------------------------------------
// Sha256Hasher — platform-specific incremental SHA-256
// ---------------------------------------------------------------------------

class Sha256Hasher {
public:
    Sha256Hasher() {
#if defined(OS_MAC)
        CC_SHA256_Init(&ctx_);
#else
        ctx_ = EVP_MD_CTX_new();
        if (ctx_) {
            EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr);
        }
#endif
    }

    ~Sha256Hasher() {
#if !defined(OS_MAC)
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
#endif
    }

    Sha256Hasher(const Sha256Hasher&) = delete;
    Sha256Hasher& operator=(const Sha256Hasher&) = delete;

    void update(const void* data, size_t len) {
        if (len == 0) return;
#if defined(OS_MAC)
        auto* p = static_cast<const uint8_t*>(data);
        while (len > 0) {
            CC_LONG chunk = static_cast<CC_LONG>(std::min(len, static_cast<size_t>(UINT32_MAX)));
            CC_SHA256_Update(&ctx_, p, chunk);
            p += chunk;
            len -= chunk;
        }
#else
        if (ctx_) {
            EVP_DigestUpdate(ctx_, data, len);
        }
#endif
    }

    std::string finalize() {
        std::array<unsigned char, 32> digest{};
#if defined(OS_MAC)
        CC_SHA256_Final(digest.data(), &ctx_);
#else
        if (ctx_) {
            unsigned int digest_len = 0;
            EVP_DigestFinal_ex(ctx_, digest.data(), &digest_len);
        }
#endif
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (unsigned char byte : digest) {
            hex << std::setw(2) << static_cast<int>(byte);
        }
        return hex.str();
    }

private:
#if defined(OS_MAC)
    CC_SHA256_CTX ctx_;
#else
    EVP_MD_CTX* ctx_ = nullptr;
#endif
};

// ---------------------------------------------------------------------------
// is_download_response / should_accumulate
// ---------------------------------------------------------------------------

static bool has_attachment_disposition(CefRefPtr<CefResponse> response) {
    CefString disposition = response->GetHeaderByName("Content-Disposition");
    std::string val = disposition.ToString();
    std::string lower;
    lower.reserve(val.size());
    for (char c : val) {
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return lower.find("attachment") != std::string::npos;
}

static bool is_binary_mime(const std::string& mime) {
    static const char* const kBinaryMimes[] = {
        "application/octet-stream",
        "application/x-msdownload",
        "application/x-executable",
        "application/zip",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/pdf",
        "application/x-dosexec",
    };
    for (const char* m : kBinaryMimes) {
        if (mime == m) return true;
    }
    return false;
}

static bool has_suspicious_extension(const std::string& url) {
    static const char* const kExtensions[] = {
        ".exe", ".dll", ".scr", ".msi", ".zip", ".rar", ".7z",
        ".bat", ".cmd", ".ps1", ".vbs", ".js",  ".hta", ".iso",
        ".img", ".cab", ".lnk",
    };

    std::string path = url;
    auto query_pos = path.find('?');
    if (query_pos != std::string::npos) path.resize(query_pos);
    auto frag_pos = path.find('#');
    if (frag_pos != std::string::npos) path.resize(frag_pos);

    // Lowercase the tail for case-insensitive extension matching
    std::string tail;
    if (path.size() > 8) {
        tail = path.substr(path.size() - 8);
    } else {
        tail = path;
    }
    for (char& c : tail) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    for (const char* ext : kExtensions) {
        size_t ext_len = std::strlen(ext);
        if (tail.size() >= ext_len &&
            tail.compare(tail.size() - ext_len, ext_len, ext) == 0) {
            return true;
        }
    }
    return false;
}

bool is_download_response(CefRefPtr<CefRequest> request,
                          CefRefPtr<CefResponse> response) {
    if (has_attachment_disposition(response)) return true;

    std::string mime = response->GetMimeType().ToString();
    if (is_binary_mime(mime)) return true;

    std::string url = request->GetURL().ToString();
    if (has_suspicious_extension(url)) return true;

    return false;
}

bool should_accumulate(CefRefPtr<CefResponse> response) {
    CefString cl_header = response->GetHeaderByName("Content-Length");
    std::string cl_str = cl_header.ToString();
    if (cl_str.empty()) return true;

    try {
        size_t content_length = std::stoull(cl_str);
        return content_length < kMaxCaptureSize;
    } catch (...) {
        return true;
    }
}

// ---------------------------------------------------------------------------
// DownloadCaptureFilter::HasherImpl
// ---------------------------------------------------------------------------

struct DownloadCaptureFilter::HasherImpl {
    Sha256Hasher hasher;
};

// ---------------------------------------------------------------------------
// DownloadCaptureFilter
// ---------------------------------------------------------------------------

DownloadCaptureFilter::DownloadCaptureFilter(const std::string& url,
                                             const std::string& mime_type,
                                             FilterCompleteCallback on_complete)
    : url_(url), mime_type_(mime_type), on_complete_(std::move(on_complete)) {}

bool DownloadCaptureFilter::InitFilter() {
    hasher_ = std::make_unique<HasherImpl>();
    buffer_.reserve(1024 * 1024);
    return true;
}

CefResponseFilter::FilterStatus DownloadCaptureFilter::Filter(
    void* data_in, size_t data_in_size, size_t& data_in_read,
    void* data_out, size_t data_out_size, size_t& data_out_written) {

    if (data_in_size == 0) {
        data_in_read = 0;
        data_out_written = 0;
        sha256_hex_ = hasher_->hasher.finalize();
        complete_ = true;
        if (on_complete_) {
            on_complete_(sha256_hex_, std::move(buffer_), url_, mime_type_);
            on_complete_ = nullptr;
        }
        return RESPONSE_FILTER_DONE;
    }

    size_t to_copy = std::min(data_in_size, data_out_size);
    std::memcpy(data_out, data_in, to_copy);
    data_in_read = to_copy;
    data_out_written = to_copy;

    hasher_->hasher.update(data_in, to_copy);

    if (!overflow_) {
        if (buffer_.size() + to_copy > kMaxCaptureSize) {
            overflow_ = true;
            buffer_.clear();
            buffer_.shrink_to_fit();
        } else {
            auto* bytes = static_cast<const uint8_t*>(data_in);
            buffer_.insert(buffer_.end(), bytes, bytes + to_copy);
        }
    }

    // DONE = all input consumed, no pending output. CEF will call again with
    // next network chunk. NEED_MORE_DATA = partial read, re-present remainder.
    return (to_copy == data_in_size) ? RESPONSE_FILTER_DONE
                                     : RESPONSE_FILTER_NEED_MORE_DATA;
}

// ---------------------------------------------------------------------------
// StreamingHashFilter::HasherImpl
// ---------------------------------------------------------------------------

struct StreamingHashFilter::HasherImpl {
    Sha256Hasher hasher;
};

// ---------------------------------------------------------------------------
// StreamingHashFilter
// ---------------------------------------------------------------------------

StreamingHashFilter::StreamingHashFilter(const std::string& url,
                                         const std::string& mime_type)
    : url_(url), mime_type_(mime_type) {}

bool StreamingHashFilter::InitFilter() {
    hasher_ = std::make_unique<HasherImpl>();
    return true;
}

CefResponseFilter::FilterStatus StreamingHashFilter::Filter(
    void* data_in, size_t data_in_size, size_t& data_in_read,
    void* data_out, size_t data_out_size, size_t& data_out_written) {

    if (data_in_size == 0) {
        data_in_read = 0;
        data_out_written = 0;
        sha256_hex_ = hasher_->hasher.finalize();
        complete_ = true;
        return RESPONSE_FILTER_DONE;
    }

    size_t to_copy = std::min(data_in_size, data_out_size);
    std::memcpy(data_out, data_in, to_copy);
    data_in_read = to_copy;
    data_out_written = to_copy;

    hasher_->hasher.update(data_in, to_copy);

    return (to_copy == data_in_size) ? RESPONSE_FILTER_DONE
                                     : RESPONSE_FILTER_NEED_MORE_DATA;
}

}  // namespace shieldtier
