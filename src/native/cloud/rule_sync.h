#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "common/json.h"
#include "common/result.h"
#include "security/rule_crypto.h"

namespace shieldtier {

class HttpClient;

struct RuleSyncConfig {
    std::string api_base_url = "https://api.shieldtier.com/v1";
    std::string api_key;
    std::string cache_dir;
    std::string license_key;
    std::string hardware_fingerprint;
    int sync_interval_seconds = 3600;
};

struct RuleManifest {
    std::string version;
    int64_t timestamp;
    std::vector<std::string> package_ids;
    std::string checksum;  // SHA-256 of concatenated package IDs
};

class RuleSync {
public:
    explicit RuleSync(const RuleSyncConfig& config);
    ~RuleSync();

    RuleSync(const RuleSync&) = delete;
    RuleSync& operator=(const RuleSync&) = delete;

    Result<int> sync();
    Result<std::vector<uint8_t>> get_rules();
    bool has_valid_cache() const;
    std::string current_version() const;
    Result<int> force_sync();

    using SyncCallback = std::function<void(const std::string& status, int progress)>;
    void set_sync_callback(SyncCallback cb);

private:
    Result<RuleManifest> fetch_manifest();
    Result<EncryptedRulePackage> download_package(const std::string& package_id);
    Result<std::vector<uint8_t>> decrypt_package(const EncryptedRulePackage& pkg);

    Result<bool> save_to_cache(const std::string& package_id,
                               const std::vector<uint8_t>& data);
    Result<std::vector<uint8_t>> load_from_cache(const std::string& package_id);
    bool is_cached(const std::string& package_id) const;
    void prune_expired_cache();

    Result<bool> save_manifest(const RuleManifest& manifest);
    Result<RuleManifest> load_cached_manifest();

    std::unordered_map<std::string, std::string> auth_headers() const;

    RuleSyncConfig config_;
    RuleManifest current_manifest_;
    std::vector<uint8_t> decryption_key_;
    std::unique_ptr<HttpClient> http_;
    SyncCallback callback_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
