#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/enrichment/http_client.h"
#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

struct EnrichmentConfig {
    std::string virustotal_api_key;
    std::string abuseipdb_api_key;
    std::string otx_api_key;
    std::string misp_api_key;
    std::string misp_base_url;  // e.g., "https://misp.your-org.com"
};

struct ProviderResult {
    std::string provider_name;
    bool found;
    int detection_count;
    int total_engines;
    std::string reputation;
    json raw_response;
};

class EnrichmentManager {
public:
    explicit EnrichmentManager(const EnrichmentConfig& config);

    Result<AnalysisEngineResult> enrich_by_hash(const std::string& sha256,
                                                 const std::string& md5 = "");

    Result<ProviderResult> query_virustotal(const std::string& hash);
    Result<ProviderResult> query_abuseipdb(const std::string& ip);
    Result<ProviderResult> query_otx(const std::string& hash);
    Result<ProviderResult> query_urlhaus(const std::string& hash);
    Result<ProviderResult> query_whois(const std::string& domain_or_ip);
    Result<ProviderResult> query_misp(const std::string& indicator);

    void set_config(const EnrichmentConfig& config);

private:
    struct CacheEntry {
        ProviderResult result;
        std::chrono::steady_clock::time_point expires_at;
    };

    std::string get_cache_key(const std::string& provider,
                              const std::string& indicator);
    void cache_result(const std::string& key, const ProviderResult& result);
    std::optional<ProviderResult> get_cached(const std::string& key);
    std::vector<Finding> generate_findings(
        const std::vector<ProviderResult>& results);

    EnrichmentConfig config_;
    mutable std::mutex config_mutex_;
    HttpClient http_client_;
    mutable std::mutex http_mutex_;

    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
    static constexpr auto kCacheTtl = std::chrono::minutes(15);

    mutable std::mutex rate_mutex_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>
        last_request_;
    void rate_limit(const std::string& provider);
};

}  // namespace shieldtier
