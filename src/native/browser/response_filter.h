#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <functional>
#include <vector>

#include "include/cef_request.h"
#include "include/cef_response.h"
#include "include/cef_response_filter.h"

namespace shieldtier {

constexpr size_t kMaxCaptureSize = 500 * 1024 * 1024;

using FilterCompleteCallback = std::function<void(
    std::string sha256, std::vector<uint8_t> data,
    std::string url, std::string mime_type)>;

bool is_download_response(CefRefPtr<CefRequest> request,
                          CefRefPtr<CefResponse> response);

bool should_accumulate(CefRefPtr<CefResponse> response);

// Captures full response body into memory (< 500MB).
// Computes SHA-256 incrementally while passing all bytes through unchanged.
class DownloadCaptureFilter : public CefResponseFilter {
public:
    DownloadCaptureFilter(const std::string& url, const std::string& mime_type,
                          FilterCompleteCallback on_complete = nullptr);
    ~DownloadCaptureFilter() override;

    bool InitFilter() override;
    FilterStatus Filter(void* data_in, size_t data_in_size,
                        size_t& data_in_read, void* data_out,
                        size_t data_out_size,
                        size_t& data_out_written) override;

    const std::vector<uint8_t>& captured_data() const { return buffer_; }
    const std::string& sha256_hex() const { return sha256_hex_; }
    const std::string& url() const { return url_; }
    const std::string& mime_type() const { return mime_type_; }
    bool is_complete() const { return complete_; }

private:
    std::string url_;
    std::string mime_type_;
    std::vector<uint8_t> buffer_;
    std::string sha256_hex_;
    bool complete_ = false;
    bool overflow_ = false;
    FilterCompleteCallback on_complete_;

    struct HasherImpl;
    std::unique_ptr<HasherImpl> hasher_;

    IMPLEMENT_REFCOUNTING(DownloadCaptureFilter);
    DISALLOW_COPY_AND_ASSIGN(DownloadCaptureFilter);
};

// Hash-only filter for large responses (>= 500MB).
// Passes all bytes through unchanged, computes SHA-256 without accumulating.
class StreamingHashFilter : public CefResponseFilter {
public:
    StreamingHashFilter(const std::string& url, const std::string& mime_type);
    ~StreamingHashFilter() override;

    bool InitFilter() override;
    FilterStatus Filter(void* data_in, size_t data_in_size,
                        size_t& data_in_read, void* data_out,
                        size_t data_out_size,
                        size_t& data_out_written) override;

    const std::string& sha256_hex() const { return sha256_hex_; }
    const std::string& url() const { return url_; }
    const std::string& mime_type() const { return mime_type_; }
    bool is_complete() const { return complete_; }

private:
    std::string url_;
    std::string mime_type_;
    std::string sha256_hex_;
    bool complete_ = false;

    struct HasherImpl;
    std::unique_ptr<HasherImpl> hasher_;

    IMPLEMENT_REFCOUNTING(StreamingHashFilter);
    DISALLOW_COPY_AND_ASSIGN(StreamingHashFilter);
};

constexpr size_t kMaxResponseBodyCaptureSize = 1 * 1024 * 1024;  // 1MB

using BodyCaptureCallback = std::function<void(std::string url, std::string body)>;

bool is_text_mime(const std::string& mime);

// Captures text-based response bodies (HTML, JSON, XML, JS, CSS) up to 1MB.
// Passes all bytes through unchanged — does not modify the response.
class ResponseBodyCaptureFilter : public CefResponseFilter {
public:
    ResponseBodyCaptureFilter(const std::string& url, const std::string& mime_type,
                              BodyCaptureCallback on_complete);
    ~ResponseBodyCaptureFilter() override;

    bool InitFilter() override;
    FilterStatus Filter(void* data_in, size_t data_in_size,
                        size_t& data_in_read, void* data_out,
                        size_t data_out_size,
                        size_t& data_out_written) override;

    const std::string& url() const { return url_; }
    const std::string& mime_type() const { return mime_type_; }

private:
    std::string url_;
    std::string mime_type_;
    std::string buffer_;
    bool overflow_ = false;
    BodyCaptureCallback on_complete_;

    IMPLEMENT_REFCOUNTING(ResponseBodyCaptureFilter);
    DISALLOW_COPY_AND_ASSIGN(ResponseBodyCaptureFilter);
};

}  // namespace shieldtier
