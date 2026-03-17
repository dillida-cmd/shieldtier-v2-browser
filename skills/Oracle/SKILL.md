---
name: Oracle
description: Use when building hash enrichment providers (VirusTotal, AbuseIPDB, OTX, URLhaus, WHOIS, MISP), email analysis (MIME parser, header analyzer), and page content analysis
---

# S6 — Oracle: Enrichment, Email & Content Analysis

## Overview

Port V1's enrichment providers, email analysis, and content analysis to C++. Enrichment uses libcurl for HTTP API calls to VirusTotal, AbuseIPDB, OTX, URLhaus, WHOIS, and MISP. Email analysis parses MIME/EML. Content analysis inspects page content for threats.

## Dependencies

- **Requires:** S0 (foundation) — libcurl, nlohmann/json
- **No blocking dependencies** — fully parallel with S3-S5, S7-S9

## File Ownership

```
src/native/analysis/enrichment/
  manager.cpp/.h      (enrichment orchestrator — parallel provider queries)
  extractors.cpp/.h   (IOC extraction: hashes, IPs, domains, URLs)
  providers/
    virustotal.cpp/.h     (VT API v3)
    abuseipdb.cpp/.h      (AbuseIPDB check endpoint)
    otx.cpp/.h            (AlienVault OTX pulse indicators)
    urlhaus.cpp/.h        (URLhaus URL/hash lookup)
    whois.cpp/.h          (WHOIS domain lookup)
    misp.cpp/.h           (MISP attribute search)

src/native/analysis/email/
  manager.cpp/.h          (email analysis orchestrator)
  parser.cpp/.h           (MIME parser — headers, parts, attachments)
  header_analyzer.cpp/.h  (SPF/DKIM/DMARC, hop analysis, authentication)
  content_analyzer.cpp/.h (body analysis — URLs, suspicious patterns)

src/native/analysis/content/
  analyzer.cpp/.h         (page content threat detection)
```

## Exit Criteria

Hash → VirusTotal + AbuseIPDB query → merged enrichment results. EML file → parsed headers, body, attachments → authentication analysis + content threat detection.

---

## Enrichment Manager

```cpp
#include <curl/curl.h>
#include <future>

class EnrichmentManager {
public:
    struct EnrichmentResult {
        nlohmann::json virustotal;
        nlohmann::json abuseipdb;
        nlohmann::json otx;
        nlohmann::json urlhaus;
        nlohmann::json whois;
        nlohmann::json misp;
        std::vector<Finding> findings;
    };

    // Query all providers in parallel
    EnrichmentResult enrich(const std::string& sha256,
                            const std::vector<std::string>& ips,
                            const std::vector<std::string>& domains) {
        EnrichmentResult result;

        // Launch parallel queries
        auto vt_future = std::async(std::launch::async, [&]() {
            return vt_provider_.lookup_hash(sha256);
        });
        auto urlhaus_future = std::async(std::launch::async, [&]() {
            return urlhaus_provider_.lookup_hash(sha256);
        });

        std::vector<std::future<nlohmann::json>> ip_futures;
        for (auto& ip : ips) {
            ip_futures.push_back(std::async(std::launch::async, [&, ip]() {
                return abuseipdb_provider_.check_ip(ip);
            }));
        }

        // Collect results
        result.virustotal = vt_future.get();
        result.urlhaus = urlhaus_future.get();

        // Merge IP results
        for (auto& f : ip_futures) {
            auto ip_result = f.get();
            if (ip_result.contains("abuse_confidence_score") &&
                ip_result["abuse_confidence_score"].get<int>() > 50) {
                result.findings.push_back({
                    "Malicious IP Detected",
                    "IP associated with abuse (score: " +
                        std::to_string(ip_result["abuse_confidence_score"].get<int>()) + ")",
                    "high", "enrichment",
                    {{"ip", ip_result["ip"]}, {"score", ip_result["abuse_confidence_score"]}}
                });
            }
        }

        return result;
    }
};
```

## libcurl HTTP Client Pattern

```cpp
// Thread-safe HTTP helper using libcurl
namespace http {

struct Response {
    int status_code;
    std::string body;
    std::string error;
};

static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* response = static_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

Response get(const std::string& url, const std::map<std::string, std::string>& headers,
             int timeout_seconds = 30) {
    Response result;
    CURL* curl = curl_easy_init();
    if (!curl) return {0, "", "curl_easy_init failed"};

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    struct curl_slist* header_list = nullptr;
    for (auto& [key, value] : headers) {
        header_list = curl_slist_append(header_list, (key + ": " + value).c_str());
    }
    if (header_list) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        result.error = curl_easy_strerror(res);
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status_code);
    }

    curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);
    return result;
}

} // namespace http
```

## VirusTotal Provider

```cpp
class VirusTotalProvider {
    std::string api_key_;

public:
    nlohmann::json lookup_hash(const std::string& sha256) {
        auto resp = http::get(
            "https://www.virustotal.com/api/v3/files/" + sha256,
            {{"x-apikey", api_key_}});

        if (resp.status_code != 200) return {{"error", resp.error}};

        auto data = nlohmann::json::parse(resp.body);
        auto& attrs = data["data"]["attributes"];

        return {
            {"sha256", sha256},
            {"detection_ratio", {
                {"malicious", attrs["last_analysis_stats"]["malicious"]},
                {"total", attrs["last_analysis_stats"]["malicious"].get<int>() +
                          attrs["last_analysis_stats"]["undetected"].get<int>()}
            }},
            {"reputation", attrs.value("reputation", 0)},
            {"tags", attrs.value("tags", nlohmann::json::array())},
            {"first_seen", attrs.value("first_submission_date", 0)},
            {"last_seen", attrs.value("last_analysis_date", 0)}
        };
    }
};
```

## AbuseIPDB Provider

```cpp
class AbuseIPDBProvider {
    std::string api_key_;

public:
    nlohmann::json check_ip(const std::string& ip) {
        auto resp = http::get(
            "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90",
            {{"Key", api_key_}, {"Accept", "application/json"}});

        if (resp.status_code != 200) return {{"error", resp.error}};

        auto data = nlohmann::json::parse(resp.body)["data"];
        return {
            {"ip", ip},
            {"abuse_confidence_score", data["abuseConfidenceScore"]},
            {"total_reports", data["totalReports"]},
            {"country_code", data["countryCode"]},
            {"isp", data["isp"]},
            {"domain", data["domain"]},
            {"is_tor", data.value("isTor", false)}
        };
    }
};
```

## IOC Extractor

```cpp
struct ExtractedIOCs {
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
    std::vector<std::string> domains;
    std::vector<std::string> urls;
    std::vector<std::string> emails;
    std::vector<std::string> hashes_md5;
    std::vector<std::string> hashes_sha256;
};

ExtractedIOCs extract_iocs(const std::string& text) {
    ExtractedIOCs result;

    // IPv4
    std::regex ipv4_re(R"(\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b)");
    // URL
    std::regex url_re(R"(https?://[^\s\"\'>]+)");
    // SHA-256
    std::regex sha256_re(R"(\b[0-9a-fA-F]{64}\b)");
    // MD5
    std::regex md5_re(R"(\b[0-9a-fA-F]{32}\b)");
    // Email
    std::regex email_re(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)");
    // Domain
    std::regex domain_re(R"(\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b)");

    auto extract = [&](const std::regex& re, std::vector<std::string>& out) {
        auto begin = std::sregex_iterator(text.begin(), text.end(), re);
        for (auto it = begin; it != std::sregex_iterator(); ++it) {
            out.push_back(it->str());
        }
    };

    extract(ipv4_re, result.ipv4);
    extract(url_re, result.urls);
    extract(sha256_re, result.hashes_sha256);
    extract(md5_re, result.hashes_md5);
    extract(email_re, result.emails);

    return result;
}
```

## Email Analysis

### MIME Parser

```cpp
struct MimePart {
    std::string content_type;
    std::string content_disposition;
    std::string content_transfer_encoding;
    std::string filename;
    std::vector<uint8_t> body;
    std::vector<MimePart> children;  // multipart
};

struct ParsedEmail {
    std::map<std::string, std::string> headers;
    std::string subject;
    std::string from;
    std::vector<std::string> to;
    std::string date;
    std::string message_id;
    std::vector<MimePart> parts;
    std::vector<FileBuffer> attachments;
};

ParsedEmail parse_eml(const uint8_t* data, size_t size) {
    ParsedEmail email;
    std::string content(data, data + size);

    // Split headers and body at first blank line
    auto header_end = content.find("\r\n\r\n");
    if (header_end == std::string::npos) header_end = content.find("\n\n");

    std::string header_section = content.substr(0, header_end);
    std::string body_section = content.substr(header_end + 2);

    // Parse headers (handle folding — lines starting with whitespace continue previous)
    parse_headers(header_section, email.headers);

    email.subject = email.headers["Subject"];
    email.from = email.headers["From"];
    email.date = email.headers["Date"];
    email.message_id = email.headers["Message-ID"];

    // Parse MIME parts recursively
    auto content_type = email.headers["Content-Type"];
    if (content_type.find("multipart/") != std::string::npos) {
        auto boundary = extract_boundary(content_type);
        email.parts = parse_multipart(body_section, boundary);
    }

    // Extract attachments
    extract_attachments(email.parts, email.attachments);

    return email;
}
```

### Header Analyzer

```cpp
struct AuthenticationResult {
    std::string spf;   // "pass", "fail", "softfail", "none"
    std::string dkim;  // "pass", "fail", "none"
    std::string dmarc; // "pass", "fail", "none"
    std::vector<Finding> findings;
};

AuthenticationResult analyze_headers(const ParsedEmail& email) {
    AuthenticationResult result;

    // Parse Authentication-Results header
    auto auth_results = email.headers.find("Authentication-Results");
    if (auth_results != email.headers.end()) {
        result.spf = extract_auth_result(auth_results->second, "spf");
        result.dkim = extract_auth_result(auth_results->second, "dkim");
        result.dmarc = extract_auth_result(auth_results->second, "dmarc");
    }

    // SPF failure
    if (result.spf == "fail") {
        result.findings.push_back({
            "SPF Failed", "Sender IP not authorized for this domain",
            "high", "email", {{"spf", result.spf}}
        });
    }

    // Analyze Received headers for hop count and suspicious relays
    auto received_headers = get_all_headers(email, "Received");
    if (received_headers.size() > 10) {
        result.findings.push_back({
            "Excessive Mail Hops",
            std::to_string(received_headers.size()) + " mail hops detected",
            "medium", "email", {{"hops", received_headers.size()}}
        });
    }

    // Check for header spoofing indicators
    auto return_path = email.headers.find("Return-Path");
    if (return_path != email.headers.end()) {
        auto from_domain = extract_domain(email.from);
        auto return_domain = extract_domain(return_path->second);
        if (from_domain != return_domain) {
            result.findings.push_back({
                "Return-Path Mismatch",
                "From domain (" + from_domain + ") differs from Return-Path (" + return_domain + ")",
                "high", "email", {}
            });
        }
    }

    return result;
}
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Not rate-limiting API calls | VT free tier: 4 req/min. Use token bucket or queue |
| Blocking main thread on HTTP | Always use std::async or thread pool for enrichment |
| Not URL-encoding query parameters | Use curl_easy_escape for URL params |
| Leaking CURL handles | Always curl_easy_cleanup, even on error paths |
| Not calling curl_global_init | Call once at startup with CURL_GLOBAL_DEFAULT |
| Parsing untrusted email headers without bounds | Malformed emails can have huge headers — limit parsing |
| Not handling base64/quoted-printable in MIME | Attachments are encoded — decode before analysis |
| Missing API key validation | Check key exists before making requests, return clear error |
