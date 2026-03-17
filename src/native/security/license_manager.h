#pragma once

#include <cstdint>
#include <mutex>
#include <string>

#include "common/json.h"
#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

enum class LicenseStatus {
    kValid,
    kExpired,
    kOfflineGrace,
    kInvalid,
    kUnactivated
};

struct LicenseInfo {
    std::string license_key;
    std::string hardware_fingerprint;
    Tier tier;
    LicenseStatus status;
    int64_t activated_at;       // epoch seconds
    int64_t last_validated_at;  // last successful server validation
    int64_t expires_at;         // license expiry (0 = perpetual)
    int days_remaining_offline; // days left in offline grace (max 30)
};

class LicenseManager {
public:
    LicenseManager();
    ~LicenseManager();

    // Activate a license key — validates against server, binds to hardware
    Result<LicenseInfo> activate(const std::string& license_key);

    // Validate current license (checks expiry, offline grace, hardware match)
    Result<LicenseInfo> validate();

    // Deactivate license (removes from secure storage)
    Result<bool> deactivate();

    // Get current license info without validation
    LicenseInfo current_info() const;

    // Check if a specific feature is available at current tier
    bool has_feature(const std::string& feature) const;

    // Derive encryption key for rule packages
    std::vector<uint8_t> derive_rule_key() const;

private:
    // Platform-specific secure storage (Keychain / DPAPI / Secret Service)
    Result<bool> store_license(const LicenseInfo& info);
    Result<LicenseInfo> load_license();
    Result<bool> delete_license();

    // Check hardware fingerprint matches stored one
    bool verify_hardware_binding() const;

    // Calculate offline grace period status
    void update_offline_grace();

    LicenseInfo info_;
    mutable std::mutex mutex_;

    static constexpr int kOfflineGraceDays = 30;
    static constexpr int64_t kSecondsPerDay = 86400;
};

}  // namespace shieldtier
