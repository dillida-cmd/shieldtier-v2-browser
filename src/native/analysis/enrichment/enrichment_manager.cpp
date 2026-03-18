#include "analysis/enrichment/enrichment_manager.h"

#include <chrono>
#include <thread>

namespace shieldtier {
namespace {

constexpr auto kVtRateInterval = std::chrono::seconds(15);
constexpr auto kDefaultRateInterval = std::chrono::seconds(1);

}  // namespace

EnrichmentManager::EnrichmentManager(const EnrichmentConfig& config)
    : config_(config) {}

void EnrichmentManager::set_config(const EnrichmentConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
}

std::string EnrichmentManager::get_cache_key(const std::string& provider,
                                              const std::string& indicator) {
    return provider + ":" + indicator;
}

void EnrichmentManager::cache_result(const std::string& key,
                                      const ProviderResult& result) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_[key] = CacheEntry{result,
                             std::chrono::steady_clock::now() + kCacheTtl};
}

std::optional<ProviderResult> EnrichmentManager::get_cached(
    const std::string& key) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) return std::nullopt;
    if (std::chrono::steady_clock::now() > it->second.expires_at) {
        cache_.erase(it);
        return std::nullopt;
    }
    return it->second.result;
}

void EnrichmentManager::rate_limit(const std::string& provider) {
    auto interval = (provider == "virustotal") ? kVtRateInterval
                                               : kDefaultRateInterval;
    std::unique_lock<std::mutex> lock(rate_mutex_);
    auto it = last_request_.find(provider);
    if (it != last_request_.end()) {
        auto elapsed = std::chrono::steady_clock::now() - it->second;
        if (elapsed < interval) {
            auto wait = interval - elapsed;
            lock.unlock();
            std::this_thread::sleep_for(wait);
            lock.lock();
        }
    }
    last_request_[provider] = std::chrono::steady_clock::now();
}

Result<ProviderResult> EnrichmentManager::query_virustotal(
    const std::string& hash) {
    if (config_.virustotal_api_key.empty()) {
        return Error("VirusTotal API key not configured", "VT_NO_KEY");
    }

    auto cache_key = get_cache_key("virustotal", hash);
    if (auto cached = get_cached(cache_key)) {
        return *cached;
    }

    rate_limit("virustotal");

    std::string url =
        "https://www.virustotal.com/api/v3/files/" + hash;
    Result<json> result = [&] {
        std::lock_guard<std::mutex> lock(http_mutex_);
        return http_client_.get_json(
            url, {{"x-apikey", config_.virustotal_api_key}});
    }();
    if (!result.ok()) return result.error();

    const auto& data = result.value();

    ProviderResult pr;
    pr.provider_name = "VirusTotal";
    pr.raw_response = data;

    if (!data.contains("data") ||
        !data["data"].contains("attributes") ||
        !data["data"]["attributes"].contains("last_analysis_stats")) {
        pr.found = false;
        pr.detection_count = 0;
        pr.total_engines = 0;
        pr.reputation = "unknown";
        cache_result(cache_key, pr);
        return pr;
    }

    const auto& stats = data["data"]["attributes"]["last_analysis_stats"];
    int malicious = stats.value("malicious", 0);
    int suspicious = stats.value("suspicious", 0);
    int harmless = stats.value("harmless", 0);
    int undetected = stats.value("undetected", 0);

    pr.found = true;
    pr.detection_count = malicious + suspicious;
    pr.total_engines = malicious + suspicious + harmless + undetected;

    if (pr.total_engines > 0) {
        double ratio =
            static_cast<double>(pr.detection_count) / pr.total_engines;
        if (ratio > 0.5) {
            pr.reputation = "malicious";
        } else if (ratio > 0.1) {
            pr.reputation = "suspicious";
        } else if (pr.detection_count > 0) {
            pr.reputation = "low_risk";
        } else {
            pr.reputation = "clean";
        }
    } else {
        pr.reputation = "unknown";
    }

    cache_result(cache_key, pr);
    return pr;
}

Result<ProviderResult> EnrichmentManager::query_otx(const std::string& hash) {
    if (config_.otx_api_key.empty()) {
        return Error("OTX API key not configured", "OTX_NO_KEY");
    }

    auto cache_key = get_cache_key("otx", hash);
    if (auto cached = get_cached(cache_key)) {
        return *cached;
    }

    rate_limit("otx");

    std::string url =
        "https://otx.alienvault.com/api/v1/indicators/file/" + hash +
        "/general";
    Result<json> result = [&] {
        std::lock_guard<std::mutex> lock(http_mutex_);
        return http_client_.get_json(
            url, {{"X-OTX-API-KEY", config_.otx_api_key}});
    }();
    if (!result.ok()) return result.error();

    const auto& data = result.value();

    ProviderResult pr;
    pr.provider_name = "OTX";
    pr.raw_response = data;
    pr.total_engines = 0;

    int pulse_count = 0;
    if (data.contains("pulse_info") &&
        data["pulse_info"].contains("count")) {
        pulse_count = data["pulse_info"]["count"].get<int>();
    }

    pr.found = pulse_count > 0;
    pr.detection_count = pulse_count;

    if (pulse_count > 10) {
        pr.reputation = "malicious";
    } else if (pulse_count > 0) {
        pr.reputation = "suspicious";
    } else {
        pr.reputation = "clean";
    }

    cache_result(cache_key, pr);
    return pr;
}

Result<ProviderResult> EnrichmentManager::query_urlhaus(
    const std::string& hash) {
    auto cache_key = get_cache_key("urlhaus", hash);
    if (auto cached = get_cached(cache_key)) {
        return *cached;
    }

    rate_limit("urlhaus");

    std::string form_data = "sha256_hash=" + hash;
    Result<HttpResponse> result = [&] {
        std::lock_guard<std::mutex> lock(http_mutex_);
        return http_client_.post_form(
            "https://urlhaus-api.abuse.ch/v1/payload/", form_data);
    }();
    if (!result.ok()) return result.error();

    const auto& response = result.value();

    ProviderResult pr;
    pr.provider_name = "URLhaus";
    pr.total_engines = 0;
    pr.detection_count = 0;

    try {
        auto data = json::parse(response.body);
        pr.raw_response = data;

        std::string query_status = data.value("query_status", "no_results");
        pr.found = (query_status == "ok");

        if (pr.found) {
            pr.detection_count = 1;
            pr.reputation = "malicious";
        } else {
            pr.reputation = "clean";
        }
    } catch (const json::parse_error&) {
        pr.found = false;
        pr.reputation = "unknown";
        pr.raw_response = {{"error", "invalid_json"}};
    }

    cache_result(cache_key, pr);
    return pr;
}

Result<ProviderResult> EnrichmentManager::query_abuseipdb(
    const std::string& ip) {
    if (config_.abuseipdb_api_key.empty()) {
        return Error("AbuseIPDB API key not configured", "ABUSEIPDB_NO_KEY");
    }

    auto cache_key = get_cache_key("abuseipdb", ip);
    if (auto cached = get_cached(cache_key)) {
        return *cached;
    }

    rate_limit("abuseipdb");

    std::string url =
        "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip;
    Result<json> result = [&] {
        std::lock_guard<std::mutex> lock(http_mutex_);
        return http_client_.get_json(
            url, {{"Key", config_.abuseipdb_api_key},
                  {"Accept", "application/json"}});
    }();
    if (!result.ok()) return result.error();

    const auto& data = result.value();

    ProviderResult pr;
    pr.provider_name = "AbuseIPDB";
    pr.raw_response = data;
    pr.total_engines = 0;

    int confidence = 0;
    if (data.contains("data") &&
        data["data"].contains("abuseConfidenceScore")) {
        confidence = data["data"]["abuseConfidenceScore"].get<int>();
    }

    pr.found = confidence > 0;
    pr.detection_count = confidence;

    if (confidence > 75) {
        pr.reputation = "malicious";
    } else if (confidence > 25) {
        pr.reputation = "suspicious";
    } else if (confidence > 0) {
        pr.reputation = "low_risk";
    } else {
        pr.reputation = "clean";
    }

    cache_result(cache_key, pr);
    return pr;
}

Result<ProviderResult> EnrichmentManager::query_whois(
    const std::string& domain_or_ip) {
    auto cache_key = get_cache_key("whois", domain_or_ip);
    if (auto cached = get_cached(cache_key)) {
        return *cached;
    }

    rate_limit("whois");

    // Determine whether this is an IP or domain based on whether it starts
    // with a digit.
    bool is_ip = !domain_or_ip.empty() && std::isdigit(domain_or_ip[0]);
    std::string url = is_ip
        ? "https://rdap.org/ip/" + domain_or_ip
        : "https://rdap.org/domain/" + domain_or_ip;

    Result<json> result = [&] {
        std::lock_guard<std::mutex> lock(http_mutex_);
        return http_client_.get_json(url);
    }();
    if (!result.ok()) return result.error();

    const auto& data = result.value();

    ProviderResult pr;
    pr.provider_name = "WHOIS";
    pr.raw_response = data;
    pr.detection_count = 0;
    pr.total_engines = 0;
    pr.found = true;

    // Check for privacy protection or missing registrant info.
    bool has_registrant = false;
    bool privacy_protected = false;
    if (data.contains("entities") && data["entities"].is_array()) {
        for (const auto& entity : data["entities"]) {
            if (entity.contains("roles") && entity["roles"].is_array()) {
                for (const auto& role : entity["roles"]) {
                    if (role.get<std::string>() == "registrant") {
                        has_registrant = true;
                    }
                }
            }
            // Check for redacted / privacy entries.
            if (entity.contains("vcardArray") && entity["vcardArray"].is_array()) {
                auto vcard_str = entity["vcardArray"].dump();
                if (vcard_str.find("REDACTED") != std::string::npos ||
                    vcard_str.find("Privacy") != std::string::npos ||
                    vcard_str.find("privacy") != std::string::npos ||
                    vcard_str.find("WhoisGuard") != std::string::npos) {
                    privacy_protected = true;
                }
            }
        }
    }

    // Check domain creation date for recency.
    bool recently_created = false;
    if (data.contains("events") && data["events"].is_array()) {
        for (const auto& event : data["events"]) {
            if (event.value("eventAction", "") == "registration") {
                std::string date_str = event.value("eventDate", "");
                if (!date_str.empty() && date_str.size() >= 10) {
                    // Parse ISO 8601 date prefix (YYYY-MM-DD).
                    try {
                        int year = std::stoi(date_str.substr(0, 4));
                        int month = std::stoi(date_str.substr(5, 2));
                        int day = std::stoi(date_str.substr(8, 2));

                        std::tm reg_tm = {};
                        reg_tm.tm_year = year - 1900;
                        reg_tm.tm_mon = month - 1;
                        reg_tm.tm_mday = day;
                        std::time_t reg_time = std::mktime(&reg_tm);

                        auto now = std::chrono::system_clock::now();
                        auto now_time_t =
                            std::chrono::system_clock::to_time_t(now);
                        double diff_days =
                            std::difftime(now_time_t, reg_time) / 86400.0;
                        if (diff_days < 30.0 && diff_days >= 0.0) {
                            recently_created = true;
                        }
                    } catch (...) {
                        // Date parsing failed; skip recency check.
                    }
                }
                break;
            }
        }
    }

    if (recently_created) {
        pr.reputation = "suspicious";
    } else if (privacy_protected || !has_registrant) {
        pr.reputation = "low_risk";
    } else {
        pr.reputation = "clean";
    }

    cache_result(cache_key, pr);
    return pr;
}

Result<ProviderResult> EnrichmentManager::query_misp(
    const std::string& indicator) {
    if (config_.misp_api_key.empty() || config_.misp_base_url.empty()) {
        return Error("MISP API key or base URL not configured", "MISP_NO_KEY");
    }

    auto cache_key = get_cache_key("misp", indicator);
    if (auto cached = get_cached(cache_key)) {
        return *cached;
    }

    rate_limit("misp");

    std::string url = config_.misp_base_url + "/attributes/restSearch";
    json request_body = {{"value", indicator}};

    Result<json> result = [&] {
        std::lock_guard<std::mutex> lock(http_mutex_);
        return http_client_.post_json(
            url, request_body,
            {{"Authorization", config_.misp_api_key},
             {"Accept", "application/json"}});
    }();
    if (!result.ok()) return result.error();

    const auto& data = result.value();

    ProviderResult pr;
    pr.provider_name = "MISP";
    pr.raw_response = data;
    pr.total_engines = 0;

    int attribute_count = 0;
    if (data.contains("response") &&
        data["response"].contains("Attribute") &&
        data["response"]["Attribute"].is_array()) {
        attribute_count =
            static_cast<int>(data["response"]["Attribute"].size());
    }

    pr.found = attribute_count > 0;
    pr.detection_count = attribute_count;

    if (attribute_count > 5) {
        pr.reputation = "malicious";
    } else if (attribute_count > 0) {
        pr.reputation = "suspicious";
    } else {
        pr.reputation = "clean";
    }

    cache_result(cache_key, pr);
    return pr;
}

std::vector<Finding> EnrichmentManager::generate_findings(
    const std::vector<ProviderResult>& results) {
    std::vector<Finding> findings;

    for (const auto& pr : results) {
        Finding finding;
        finding.engine = AnalysisEngine::kEnrichment;

        if (pr.provider_name == "VirusTotal") {
            finding.title = "VirusTotal: " +
                            std::to_string(pr.detection_count) + "/" +
                            std::to_string(pr.total_engines) + " detections";
            finding.description =
                "File scanned by VirusTotal with " +
                std::to_string(pr.detection_count) +
                " detections out of " +
                std::to_string(pr.total_engines) + " engines.";

            if (pr.detection_count > 5) {
                finding.severity = Severity::kHigh;
            } else if (pr.detection_count > 0) {
                finding.severity = Severity::kMedium;
            } else {
                finding.severity = Severity::kInfo;
            }
        } else if (pr.provider_name == "OTX") {
            finding.title = "OTX: " +
                            std::to_string(pr.detection_count) +
                            " pulse(s) reference this indicator";
            finding.description =
                "AlienVault OTX shows " +
                std::to_string(pr.detection_count) +
                " threat intelligence pulse(s) referencing this hash.";

            if (pr.detection_count > 0) {
                finding.severity = Severity::kMedium;
            } else {
                finding.severity = Severity::kInfo;
            }
        } else if (pr.provider_name == "URLhaus") {
            finding.title = "URLhaus: " +
                            std::string(pr.found ? "known malware payload"
                                                 : "not found");
            finding.description =
                pr.found
                    ? "This file is a known malware payload tracked by URLhaus."
                    : "File not found in URLhaus database.";

            finding.severity = pr.found ? Severity::kHigh : Severity::kInfo;
        } else if (pr.provider_name == "AbuseIPDB") {
            finding.title = "AbuseIPDB: confidence score " +
                            std::to_string(pr.detection_count) + "%";
            finding.description =
                "AbuseIPDB reports an abuse confidence score of " +
                std::to_string(pr.detection_count) + "%.";

            if (pr.detection_count > 75) {
                finding.severity = Severity::kHigh;
            } else if (pr.detection_count > 25) {
                finding.severity = Severity::kMedium;
            } else {
                finding.severity = Severity::kInfo;
            }
        } else if (pr.provider_name == "WHOIS") {
            finding.title = "WHOIS: " + pr.reputation;
            finding.description =
                "WHOIS/RDAP lookup completed with reputation: " +
                pr.reputation + ".";

            if (pr.reputation == "suspicious") {
                finding.severity = Severity::kMedium;
            } else {
                finding.severity = Severity::kInfo;
            }
        } else if (pr.provider_name == "MISP") {
            finding.title = "MISP: " +
                            std::to_string(pr.detection_count) +
                            " matching attribute(s)";
            finding.description =
                "MISP threat intelligence platform returned " +
                std::to_string(pr.detection_count) +
                " matching attribute(s) for this indicator.";

            if (pr.detection_count > 5) {
                finding.severity = Severity::kHigh;
            } else if (pr.detection_count > 0) {
                finding.severity = Severity::kMedium;
            } else {
                finding.severity = Severity::kInfo;
            }
        }

        finding.metadata = {
            {"provider", pr.provider_name},
            {"found", pr.found},
            {"detection_count", pr.detection_count},
            {"total_engines", pr.total_engines},
            {"reputation", pr.reputation},
        };

        findings.push_back(std::move(finding));
    }

    return findings;
}

Result<AnalysisEngineResult> EnrichmentManager::enrich_by_hash(
    const std::string& sha256, const std::string& md5) {
    auto start = std::chrono::steady_clock::now();

    const std::string& hash = sha256.empty() ? md5 : sha256;
    if (hash.empty()) {
        return Error("No hash provided for enrichment", "NO_HASH");
    }

    std::vector<ProviderResult> results;
    json errors = json::array();

    // Query VirusTotal
    if (!config_.virustotal_api_key.empty()) {
        auto vt = query_virustotal(hash);
        if (vt.ok()) {
            results.push_back(std::move(vt.value()));
        } else {
            errors.push_back({{"provider", "VirusTotal"},
                              {"error", vt.error().message}});
        }
    }

    // Query OTX
    if (!config_.otx_api_key.empty()) {
        auto otx = query_otx(hash);
        if (otx.ok()) {
            results.push_back(std::move(otx.value()));
        } else {
            errors.push_back({{"provider", "OTX"},
                              {"error", otx.error().message}});
        }
    }

    // Query URLhaus (no API key required)
    {
        auto uh = query_urlhaus(hash);
        if (uh.ok()) {
            results.push_back(std::move(uh.value()));
        } else {
            errors.push_back({{"provider", "URLhaus"},
                              {"error", uh.error().message}});
        }
    }

    // Query MISP
    if (!config_.misp_api_key.empty() && !config_.misp_base_url.empty()) {
        auto misp = query_misp(hash);
        if (misp.ok()) {
            results.push_back(std::move(misp.value()));
        } else {
            errors.push_back({{"provider", "MISP"},
                              {"error", misp.error().message}});
        }
    }

    auto end = std::chrono::steady_clock::now();
    double duration_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    AnalysisEngineResult engine_result;
    engine_result.engine = AnalysisEngine::kEnrichment;
    engine_result.success = !results.empty();
    engine_result.duration_ms = duration_ms;
    engine_result.findings = generate_findings(results);

    if (!engine_result.success) {
        engine_result.error = "All enrichment providers failed";
    }

    engine_result.raw_output = {
        {"hash", hash},
        {"providers_queried", results.size()},
        {"errors", errors},
    };

    for (const auto& pr : results) {
        engine_result.raw_output[pr.provider_name] = {
            {"found", pr.found},
            {"detection_count", pr.detection_count},
            {"reputation", pr.reputation},
        };
    }

    return engine_result;
}

}  // namespace shieldtier
