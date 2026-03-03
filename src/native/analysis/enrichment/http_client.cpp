#include "analysis/enrichment/http_client.h"

#include <mutex>

#include <curl/curl.h>

namespace shieldtier {
namespace {

std::once_flag g_curl_init_flag;

void ensure_curl_initialized() {
    std::call_once(g_curl_init_flag, [] {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });
}

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* buffer = static_cast<std::string*>(userdata);
    size_t total = size * nmemb;
    buffer->append(ptr, total);
    return total;
}

size_t header_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* headers =
        static_cast<std::unordered_map<std::string, std::string>*>(userdata);
    size_t total = size * nmemb;
    std::string line(ptr, total);

    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = line.substr(0, colon);
        std::string value = line.substr(colon + 1);

        // Trim leading/trailing whitespace from value
        auto start = value.find_first_not_of(" \t");
        auto end = value.find_last_not_of(" \t\r\n");
        if (start != std::string::npos && end != std::string::npos) {
            value = value.substr(start, end - start + 1);
        }

        (*headers)[key] = value;
    }
    return total;
}

}  // namespace

struct HttpClient::Impl {
    CURL* handle = nullptr;
    long timeout_seconds = 15;
    std::string user_agent = "ShieldTier/2.0";

    Impl() {
        ensure_curl_initialized();
        handle = curl_easy_init();
    }

    ~Impl() {
        if (handle) {
            curl_easy_cleanup(handle);
        }
    }

    void apply_defaults() {
        curl_easy_reset(handle);
        curl_easy_setopt(handle, CURLOPT_TIMEOUT, timeout_seconds);
        curl_easy_setopt(handle, CURLOPT_USERAGENT, user_agent.c_str());
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 5L);
    }

    Result<HttpResponse> perform(
        const std::string& url,
        const std::unordered_map<std::string, std::string>& headers,
        const std::string* post_data = nullptr,
        bool is_form = false) {
        if (!handle) {
            return Error("CURL handle not initialized", "CURL_INIT");
        }

        apply_defaults();

        std::string response_body;
        std::unordered_map<std::string, std::string> response_headers;

        curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &response_body);
        curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(handle, CURLOPT_HEADERDATA, &response_headers);

        struct curl_slist* header_list = nullptr;
        for (const auto& [key, value] : headers) {
            std::string header = key + ": " + value;
            auto* new_list = curl_slist_append(header_list, header.c_str());
            if (!new_list) {
                if (header_list) curl_slist_free_all(header_list);
                return Error("Failed to build HTTP headers", "CURL_HEADER");
            }
            header_list = new_list;
        }

        if (post_data) {
            curl_easy_setopt(handle, CURLOPT_POST, 1L);
            curl_easy_setopt(handle, CURLOPT_POSTFIELDS, post_data->c_str());
            curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE,
                             static_cast<long>(post_data->size()));
            const char* ct = is_form
                ? "Content-Type: application/x-www-form-urlencoded"
                : "Content-Type: application/json";
            auto* new_list = curl_slist_append(header_list, ct);
            if (!new_list) {
                if (header_list) curl_slist_free_all(header_list);
                return Error("Failed to build HTTP headers", "CURL_HEADER");
            }
            header_list = new_list;
        }

        if (header_list) {
            curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);
        }

        CURLcode res = curl_easy_perform(handle);

        if (header_list) {
            curl_slist_free_all(header_list);
        }

        if (res != CURLE_OK) {
            return Error(
                std::string("HTTP request failed: ") +
                    curl_easy_strerror(res),
                "CURL_" + std::to_string(static_cast<int>(res)));
        }

        long status_code = 0;
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status_code);

        HttpResponse response;
        response.status_code = static_cast<int>(status_code);
        response.body = std::move(response_body);
        response.headers = std::move(response_headers);

        return response;
    }
};

HttpClient::HttpClient() : impl_(std::make_unique<Impl>()) {}

HttpClient::~HttpClient() = default;

Result<json> HttpClient::get_json(
    const std::string& url,
    const std::unordered_map<std::string, std::string>& headers) {
    auto result = impl_->perform(url, headers);
    if (!result.ok()) return result.error();

    const auto& response = result.value();
    if (response.status_code < 200 || response.status_code >= 300) {
        return Error(
            "HTTP " + std::to_string(response.status_code) + ": " +
                response.body.substr(0, 200),
            "HTTP_" + std::to_string(response.status_code));
    }

    try {
        return json::parse(response.body);
    } catch (const json::parse_error& e) {
        return Error(std::string("JSON parse error: ") + e.what(),
                     "JSON_PARSE");
    }
}

Result<json> HttpClient::post_json(
    const std::string& url, const json& body,
    const std::unordered_map<std::string, std::string>& headers) {
    std::string body_str = body.dump();
    auto result = impl_->perform(url, headers, &body_str);
    if (!result.ok()) return result.error();

    const auto& response = result.value();
    if (response.status_code < 200 || response.status_code >= 300) {
        return Error(
            "HTTP " + std::to_string(response.status_code) + ": " +
                response.body.substr(0, 200),
            "HTTP_" + std::to_string(response.status_code));
    }

    try {
        return json::parse(response.body);
    } catch (const json::parse_error& e) {
        return Error(std::string("JSON parse error: ") + e.what(),
                     "JSON_PARSE");
    }
}

Result<HttpResponse> HttpClient::get(
    const std::string& url,
    const std::unordered_map<std::string, std::string>& headers) {
    return impl_->perform(url, headers);
}

Result<HttpResponse> HttpClient::post_form(
    const std::string& url, const std::string& form_data,
    const std::unordered_map<std::string, std::string>& headers) {
    return impl_->perform(url, headers, &form_data, true);
}

void HttpClient::set_timeout(long timeout_seconds) {
    impl_->timeout_seconds = timeout_seconds;
}

void HttpClient::set_user_agent(const std::string& user_agent) {
    impl_->user_agent = user_agent;
}

}  // namespace shieldtier
