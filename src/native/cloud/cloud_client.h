#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/json.h"
#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

class HttpClient;

struct CloudConfig {
    std::string api_base_url = "https://api.shieldtier.com/v1";
    std::string api_key;
    int timeout_seconds = 30;
};

struct CloudAnalysisRequest {
    std::string sha256;
    std::string file_type;
    size_t file_size;
    json yara_matches;
    json pe_features;
    json behavior_features;
    json network_features;
    json script_features;
    int local_threat_score;
};

struct CloudAnalysisResponse {
    bool success;
    Verdict verdict;
    double confidence;
    int cloud_threat_score;
    std::vector<Finding> additional_findings;
    std::vector<std::string> mitre_techniques;
    json threat_intel;
    json ml_scores;
};

class CloudClient {
public:
    explicit CloudClient(const CloudConfig& config = {});
    ~CloudClient();

    CloudClient(const CloudClient&) = delete;
    CloudClient& operator=(const CloudClient&) = delete;

    Result<CloudAnalysisResponse> analyze(const CloudAnalysisRequest& request);
    Result<bool> health_check();
    Result<json> get_threat_intel(const std::string& ioc_type,
                                  const std::string& ioc_value);
    Result<bool> submit_verdict(const std::string& sha256,
                                const ThreatVerdict& verdict);

    void set_api_key(const std::string& key);
    bool is_configured() const;

private:
    std::unordered_map<std::string, std::string> auth_headers() const;

    CloudConfig config_;
    std::unique_ptr<HttpClient> http_;
};

}  // namespace shieldtier
