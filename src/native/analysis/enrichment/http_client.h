#pragma once

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

struct HttpResponse {
    int status_code;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    Result<json> get_json(
        const std::string& url,
        const std::unordered_map<std::string, std::string>& headers = {});

    Result<json> post_json(
        const std::string& url, const json& body,
        const std::unordered_map<std::string, std::string>& headers = {});

    Result<HttpResponse> get(
        const std::string& url,
        const std::unordered_map<std::string, std::string>& headers = {});

    Result<HttpResponse> post_form(
        const std::string& url, const std::string& form_data,
        const std::unordered_map<std::string, std::string>& headers = {});

    void set_timeout(long timeout_seconds);
    void set_user_agent(const std::string& user_agent);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace shieldtier
