#pragma once

#include <string>
#include <vector>

#include "analysis/enrichment/http_client.h"
#include "common/json.h"
#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

/// Result from a cloud sandbox submission or poll.
struct CloudSandboxResult {
    std::string provider;     // "virustotal", "hybridanalysis", "joesandbox", "cuckoo"
    std::string status;       // "submitted", "queued", "analyzing", "complete", "error"
    std::string submission_id;
    std::string report_url;
    std::string verdict;      // "malicious", "suspicious", "clean"
    int score = 0;            // 0-100 normalized
    json details;
    int64_t timestamp = 0;
    std::string error;
};

/// Configuration for cloud sandbox API keys.
struct CloudSandboxConfig {
    std::string virustotal_api_key;
    std::string hybridanalysis_api_key;
    std::string joesandbox_api_key;
    std::string cuckoo_url;    // Self-hosted instance URL
    std::string cuckoo_token;  // API bearer token
};

/// Cloud sandbox submission manager.
/// Submits files to external sandbox services for dynamic analysis.
class CloudSandboxManager {
public:
    explicit CloudSandboxManager(const CloudSandboxConfig& config);

    void set_config(const CloudSandboxConfig& config);

    /// Submit a file to all configured sandbox providers.
    /// Returns a list of submission results (one per provider).
    std::vector<CloudSandboxResult> submit(const FileBuffer& file);

    /// Poll a specific submission for results.
    CloudSandboxResult poll(const std::string& provider,
                            const std::string& submission_id,
                            const std::string& sha256 = "");

    /// Submit to individual providers.
    Result<CloudSandboxResult> submit_virustotal(const FileBuffer& file);
    Result<CloudSandboxResult> submit_hybridanalysis(const FileBuffer& file);
    Result<CloudSandboxResult> submit_joesandbox(const FileBuffer& file);
    Result<CloudSandboxResult> submit_cuckoo(const FileBuffer& file);

    /// Poll individual providers.
    Result<CloudSandboxResult> poll_virustotal(const std::string& analysis_id);
    Result<CloudSandboxResult> poll_hybridanalysis(const std::string& sha256);
    Result<CloudSandboxResult> poll_joesandbox(const std::string& web_id);
    Result<CloudSandboxResult> poll_cuckoo(const std::string& task_id);

private:
    CloudSandboxConfig config_;
    std::mutex config_mutex_;
    HttpClient http_;
    std::mutex http_mutex_;

    static constexpr size_t kMaxUploadSize = 32 * 1024 * 1024;  // 32 MB

    std::string build_multipart(const std::string& boundary,
                                 const std::string& field_name,
                                 const std::string& filename,
                                 const uint8_t* data, size_t size,
                                 const std::vector<std::pair<std::string, std::string>>& extra_fields = {});

    int64_t now_ms() const;
};

}  // namespace shieldtier
