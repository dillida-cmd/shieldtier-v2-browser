#include "analysis/threatfeed/threat_feed_manager.h"

#include <algorithm>
#include <chrono>

#include "common/json.h"

namespace shieldtier {
namespace {

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

constexpr size_t kMaxIndicatorsPerFeed = 10000;

std::string extract_host_from_url(const std::string& url) {
    auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) return {};

    size_t host_start = scheme_end + 3;
    size_t host_end = url.find_first_of(":/", host_start);
    if (host_end == std::string::npos) host_end = url.size();

    return url.substr(host_start, host_end - host_start);
}

bool looks_like_ip(const std::string& host) {
    if (host.empty()) return false;
    int dots = 0;
    for (char c : host) {
        if (c == '.') { ++dots; }
        else if (c < '0' || c > '9') return false;
    }
    return dots == 3;
}

}  // namespace

ThreatFeedManager::ThreatFeedManager() {
    http_client_.set_user_agent("ShieldTier/2.0");
    http_client_.set_timeout(30);
}

Result<bool> ThreatFeedManager::update_feeds() {
    auto urls_result = fetch_abuse_ch_urls();
    auto hashes_result = fetch_abuse_ch_hashes();

    if (!urls_result.ok() && !hashes_result.ok()) {
        return Error(
            "All feeds failed: " + urls_result.error().message +
                "; " + hashes_result.error().message,
            "FEED_ALL_FAILED");
    }

    std::lock_guard<std::mutex> lock(mutex_);
    ip_set_.clear();
    domain_set_.clear();
    hash_set_.clear();
    url_set_.clear();
    all_indicators_.clear();

    if (urls_result.ok()) {
        index_indicators(urls_result.value());
    }
    if (hashes_result.ok()) {
        index_indicators(hashes_result.value());
    }

    return true;
}

Result<std::vector<ThreatIndicator>> ThreatFeedManager::fetch_abuse_ch_urls() {
    auto result = http_client_.post_form(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/", "");
    if (!result.ok()) return result.error();

    const auto& response = result.value();
    if (response.status_code < 200 || response.status_code >= 300) {
        return Error(
            "URLhaus HTTP " + std::to_string(response.status_code),
            "URLHAUS_HTTP");
    }

    json data;
    try {
        data = json::parse(response.body);
    } catch (const json::parse_error& e) {
        return Error(std::string("URLhaus JSON parse error: ") + e.what(),
                     "URLHAUS_JSON");
    }

    std::vector<ThreatIndicator> indicators;

    if (!data.contains("urls") || !data["urls"].is_array()) {
        return indicators;
    }

    for (const auto& entry : data["urls"]) {
        if (indicators.size() >= kMaxIndicatorsPerFeed) break;

        std::string url_val = entry.value("url", "");
        if (url_val.empty()) continue;

        ThreatIndicator ti;
        ti.type = "url";
        ti.value = url_val;
        ti.source = "abuse.ch URLhaus";
        ti.description = entry.value("threat", "");
        ti.first_seen = 0;
        ti.last_seen = 0;
        indicators.push_back(std::move(ti));

        // Extract host as a domain or IP indicator
        std::string host = extract_host_from_url(url_val);
        if (!host.empty() && indicators.size() < kMaxIndicatorsPerFeed) {
            ThreatIndicator host_ti;
            host_ti.type = looks_like_ip(host) ? "ip" : "domain";
            host_ti.value = host;
            host_ti.source = "abuse.ch URLhaus";
            host_ti.description = "Extracted from malicious URL";
            host_ti.first_seen = 0;
            host_ti.last_seen = 0;
            indicators.push_back(std::move(host_ti));
        }
    }

    return indicators;
}

Result<std::vector<ThreatIndicator>> ThreatFeedManager::fetch_abuse_ch_hashes() {
    auto result = http_client_.post_form(
        "https://mb-api.abuse.ch/api/v1/", "query=get_recent&selector=100");
    if (!result.ok()) return result.error();

    const auto& response = result.value();
    if (response.status_code < 200 || response.status_code >= 300) {
        return Error(
            "MalwareBazaar HTTP " + std::to_string(response.status_code),
            "MALBAZAAR_HTTP");
    }

    json data;
    try {
        data = json::parse(response.body);
    } catch (const json::parse_error& e) {
        return Error(
            std::string("MalwareBazaar JSON parse error: ") + e.what(),
            "MALBAZAAR_JSON");
    }

    std::vector<ThreatIndicator> indicators;

    if (!data.contains("data") || !data["data"].is_array()) {
        return indicators;
    }

    for (const auto& entry : data["data"]) {
        if (indicators.size() >= kMaxIndicatorsPerFeed) break;

        std::string sha256 = entry.value("sha256_hash", "");
        std::string md5 = entry.value("md5_hash", "");
        std::string file_type = entry.value("file_type", "");
        std::string signature = entry.value("signature", "");

        std::string desc = signature.empty()
            ? file_type
            : signature + " (" + file_type + ")";

        if (!sha256.empty()) {
            ThreatIndicator ti;
            ti.type = "hash";
            ti.value = sha256;
            ti.source = "abuse.ch MalwareBazaar";
            ti.description = desc;
            ti.first_seen = 0;
            ti.last_seen = 0;
            indicators.push_back(std::move(ti));
        }

        if (!md5.empty() && indicators.size() < kMaxIndicatorsPerFeed) {
            ThreatIndicator ti;
            ti.type = "hash";
            ti.value = md5;
            ti.source = "abuse.ch MalwareBazaar";
            ti.description = desc;
            ti.first_seen = 0;
            ti.last_seen = 0;
            indicators.push_back(std::move(ti));
        }
    }

    return indicators;
}

void ThreatFeedManager::index_indicators(
    const std::vector<ThreatIndicator>& indicators) {
    for (const auto& ti : indicators) {
        if (ti.type == "ip") {
            ip_set_.insert(ti.value);
        } else if (ti.type == "domain") {
            domain_set_.insert(ti.value);
        } else if (ti.type == "hash") {
            hash_set_.insert(to_lower(ti.value));
        } else if (ti.type == "url") {
            url_set_.insert(ti.value);
        }
        all_indicators_.push_back(ti);
    }
}

bool ThreatFeedManager::is_known_threat(const std::string& type,
                                         const std::string& value) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (type == "ip") return ip_set_.count(value) > 0;
    if (type == "domain") return domain_set_.count(value) > 0;
    if (type == "hash") return hash_set_.count(to_lower(value)) > 0;
    if (type == "url") return url_set_.count(value) > 0;

    return false;
}

std::vector<ThreatIndicator> ThreatFeedManager::lookup(
    const std::string& type, const std::string& value) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ThreatIndicator> matches;
    for (const auto& ti : all_indicators_) {
        if (ti.type == type && ti.value == value) {
            matches.push_back(ti);
        }
    }
    return matches;
}

size_t ThreatFeedManager::indicator_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return all_indicators_.size();
}

}  // namespace shieldtier
