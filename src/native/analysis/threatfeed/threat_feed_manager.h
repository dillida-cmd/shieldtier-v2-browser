#pragma once

#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "analysis/enrichment/http_client.h"
#include "common/result.h"

namespace shieldtier {

struct ThreatIndicator {
    std::string type;     // "ip", "domain", "hash", "url"
    std::string value;
    std::string source;
    std::string description;
    int64_t first_seen;
    int64_t last_seen;
};

class ThreatFeedManager {
public:
    ThreatFeedManager();

    Result<bool> update_feeds();
    bool is_known_threat(const std::string& type, const std::string& value) const;
    std::vector<ThreatIndicator> lookup(const std::string& type,
                                         const std::string& value) const;
    size_t indicator_count() const;

private:
    Result<std::vector<ThreatIndicator>> fetch_abuse_ch_urls();
    Result<std::vector<ThreatIndicator>> fetch_abuse_ch_hashes();
    void index_indicators(const std::vector<ThreatIndicator>& indicators);

    std::unordered_set<std::string> ip_set_;
    std::unordered_set<std::string> domain_set_;
    std::unordered_set<std::string> hash_set_;
    std::unordered_set<std::string> url_set_;
    std::vector<ThreatIndicator> all_indicators_;
    mutable std::mutex mutex_;
    HttpClient http_client_;
};

}  // namespace shieldtier
