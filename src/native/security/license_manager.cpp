#include "security/license_manager.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <set>
#include <unordered_map>

#include "security/hardware_fingerprint.h"
#include "security/rule_crypto.h"

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#elif defined(__linux__)
#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#include <dpapi.h>
#include <shlobj.h>
#pragma comment(lib, "crypt32.lib")
#endif

namespace shieldtier {

namespace {

static const std::unordered_map<std::string, std::set<std::string>> kTierFeatures = {
    {"free", {"basic_analysis"}},
    {"pro", {"basic_analysis", "yara_premium", "sandbox", "email_analysis"}},
    {"team", {"basic_analysis", "yara_premium", "sandbox", "email_analysis",
              "collaboration", "threat_feeds"}},
    {"enterprise", {"basic_analysis", "yara_premium", "sandbox", "email_analysis",
                    "collaboration", "threat_feeds", "server_scoring",
                    "custom_rules", "vm_sandbox"}},
};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string tier_to_string(Tier tier) {
    switch (tier) {
        case Tier::kFree:       return "free";
        case Tier::kPro:        return "pro";
        case Tier::kTeam:       return "team";
        case Tier::kEnterprise: return "enterprise";
    }
    return "free";
}

Tier tier_from_string(const std::string& s) {
    if (s == "pro") return Tier::kPro;
    if (s == "team") return Tier::kTeam;
    if (s == "enterprise") return Tier::kEnterprise;
    return Tier::kFree;
}

json license_to_json(const LicenseInfo& info) {
    return json{
        {"key", info.license_key},
        {"fingerprint", info.hardware_fingerprint},
        {"tier", tier_to_string(info.tier)},
        {"activated_at", info.activated_at},
        {"last_validated_at", info.last_validated_at},
        {"expires_at", info.expires_at},
    };
}

LicenseInfo json_to_license(const json& j) {
    LicenseInfo info;
    info.license_key = j.value("key", "");
    info.hardware_fingerprint = j.value("fingerprint", "");
    info.tier = tier_from_string(j.value("tier", "free"));
    info.status = LicenseStatus::kValid;
    info.activated_at = j.value("activated_at", int64_t{0});
    info.last_validated_at = j.value("last_validated_at", int64_t{0});
    info.expires_at = j.value("expires_at", int64_t{0});
    info.days_remaining_offline = 30;
    return info;
}

#if defined(__linux__)
// XOR-based obfuscation using hardware fingerprint as repeating key
std::string xor_obfuscate(const std::string& data, const std::string& key) {
    if (key.empty()) return data;
    std::string result(data.size(), '\0');
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = static_cast<char>(data[i] ^ key[i % key.size()]);
    }
    return result;
}

std::string get_config_dir() {
    const char* home = std::getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) return "";
    return std::string(home) + "/.config/shieldtier";
}
#endif

#if defined(_WIN32)
std::string get_appdata_dir() {
    char path[MAX_PATH]{};
    if (SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path) == S_OK) {
        return std::string(path) + "\\ShieldTier";
    }
    return "";
}
#endif

}  // namespace

// --------------------------------------------------------------------------
// Construction / destruction
// --------------------------------------------------------------------------

LicenseManager::LicenseManager()
    : info_{"", "", Tier::kFree, LicenseStatus::kUnactivated, 0, 0, 0, 0} {
    auto loaded = load_license();
    if (loaded.ok()) {
        info_ = loaded.value();
    }
}

LicenseManager::~LicenseManager() = default;

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

Result<LicenseInfo> LicenseManager::activate(const std::string& license_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string fingerprint = HardwareFingerprint::generate();
    int64_t now = now_epoch();

    // In production, tier would come from server validation response.
    // For now, default to kFree until server confirms.
    info_.license_key = license_key;
    info_.hardware_fingerprint = fingerprint;
    info_.tier = Tier::kFree;
    info_.status = LicenseStatus::kValid;
    info_.activated_at = now;
    info_.last_validated_at = now;
    info_.expires_at = 0;  // perpetual until server says otherwise
    info_.days_remaining_offline = kOfflineGraceDays;

    auto store_result = store_license(info_);
    if (!store_result.ok()) {
        return Error(store_result.error().message, store_result.error().code);
    }

    return info_;
}

Result<LicenseInfo> LicenseManager::validate() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (info_.status == LicenseStatus::kUnactivated) {
        auto loaded = load_license();
        if (!loaded.ok()) {
            return Error("No license activated", "LICENSE_NOT_FOUND");
        }
        info_ = loaded.value();
    }

    if (!verify_hardware_binding()) {
        info_.status = LicenseStatus::kInvalid;
        return Error("Hardware mismatch — license bound to different machine",
                     "HARDWARE_MISMATCH");
    }

    // Check hard expiry (non-perpetual licenses)
    if (info_.expires_at > 0 && now_epoch() > info_.expires_at) {
        info_.status = LicenseStatus::kExpired;
        return Error("License has expired", "LICENSE_EXPIRED");
    }

    update_offline_grace();

    if (info_.days_remaining_offline <= 0) {
        info_.status = LicenseStatus::kExpired;
        return Error("Offline grace period exceeded — connect to validate",
                     "OFFLINE_GRACE_EXPIRED");
    }

    if (info_.days_remaining_offline < kOfflineGraceDays) {
        info_.status = LicenseStatus::kOfflineGrace;
    } else {
        info_.status = LicenseStatus::kValid;
    }

    return info_;
}

Result<bool> LicenseManager::deactivate() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto del_result = delete_license();
    if (!del_result.ok()) {
        return Error(del_result.error().message, del_result.error().code);
    }

    info_ = {"", "", Tier::kFree, LicenseStatus::kUnactivated, 0, 0, 0, 0};
    return true;
}

LicenseInfo LicenseManager::current_info() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return info_;
}

bool LicenseManager::has_feature(const std::string& feature) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (info_.status == LicenseStatus::kUnactivated ||
        info_.status == LicenseStatus::kInvalid ||
        info_.status == LicenseStatus::kExpired) {
        return false;
    }

    std::string tier_str = tier_to_string(info_.tier);
    auto it = kTierFeatures.find(tier_str);
    if (it == kTierFeatures.end()) return false;
    return it->second.count(feature) > 0;
}

std::vector<uint8_t> LicenseManager::derive_rule_key() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return RuleCrypto::derive_key(info_.license_key, info_.hardware_fingerprint);
}

// --------------------------------------------------------------------------
// Private — hardware binding verification
// --------------------------------------------------------------------------

bool LicenseManager::verify_hardware_binding() const {
    if (info_.hardware_fingerprint.empty()) return false;
    return HardwareFingerprint::generate() == info_.hardware_fingerprint;
}

// --------------------------------------------------------------------------
// Private — offline grace calculation
// --------------------------------------------------------------------------

void LicenseManager::update_offline_grace() {
    int64_t elapsed = now_epoch() - info_.last_validated_at;
    int days_since = static_cast<int>(elapsed / kSecondsPerDay);
    info_.days_remaining_offline = std::max(0, kOfflineGraceDays - days_since);
}

// --------------------------------------------------------------------------
// Private — platform-specific secure storage
// --------------------------------------------------------------------------

#if defined(__APPLE__)
// macOS: Security.framework Keychain

static const CFStringRef kServiceName = CFSTR("com.shieldtier.license");
static const CFStringRef kAccountName = CFSTR("license_data");

Result<bool> LicenseManager::store_license(const LicenseInfo& info) {
    std::string payload = license_to_json(info).dump();
    CFDataRef data = CFDataCreate(
        kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(payload.data()),
        static_cast<CFIndex>(payload.size()));
    if (!data) return Error("Failed to create CFData", "KEYCHAIN_ERROR");

    // Delete existing item first (update semantics)
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 4, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, kServiceName);
    CFDictionarySetValue(query, kSecAttrAccount, kAccountName);
    SecItemDelete(query);

    CFDictionarySetValue(query, kSecValueData, data);
    OSStatus status = SecItemAdd(query, nullptr);

    CFRelease(data);
    CFRelease(query);

    if (status != errSecSuccess) {
        return Error("Keychain store failed: " + std::to_string(status), "KEYCHAIN_ERROR");
    }
    return true;
}

Result<LicenseInfo> LicenseManager::load_license() {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 5, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, kServiceName);
    CFDictionarySetValue(query, kSecAttrAccount, kAccountName);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = nullptr;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);

    if (status != errSecSuccess || !result) {
        return Error("No license in Keychain", "KEYCHAIN_NOT_FOUND");
    }

    CFDataRef data = static_cast<CFDataRef>(result);
    std::string payload(
        reinterpret_cast<const char*>(CFDataGetBytePtr(data)),
        static_cast<size_t>(CFDataGetLength(data)));
    CFRelease(result);

    json j = parse_json_safe(payload);
    if (j.contains("error")) {
        return Error("Corrupt license data in Keychain", "KEYCHAIN_CORRUPT");
    }
    return json_to_license(j);
}

Result<bool> LicenseManager::delete_license() {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 3, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, kServiceName);
    CFDictionarySetValue(query, kSecAttrAccount, kAccountName);

    OSStatus status = SecItemDelete(query);
    CFRelease(query);

    if (status != errSecSuccess && status != errSecItemNotFound) {
        return Error("Keychain delete failed: " + std::to_string(status), "KEYCHAIN_ERROR");
    }
    return true;
}

#elif defined(__linux__)
// Linux: file-based with XOR obfuscation using hardware fingerprint

Result<bool> LicenseManager::store_license(const LicenseInfo& info) {
    std::string dir = get_config_dir();
    if (dir.empty()) return Error("Cannot determine config directory", "STORAGE_ERROR");

    mkdir(dir.c_str(), 0700);

    std::string payload = license_to_json(info).dump();
    std::string key = HardwareFingerprint::generate();
    std::string encrypted = xor_obfuscate(payload, key);

    std::string path = dir + "/license.dat";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return Error("Failed to write license file", "STORAGE_ERROR");
    }
    out.write(encrypted.data(), static_cast<std::streamsize>(encrypted.size()));
    out.close();

    chmod(path.c_str(), 0600);
    return true;
}

Result<LicenseInfo> LicenseManager::load_license() {
    std::string dir = get_config_dir();
    if (dir.empty()) return Error("Cannot determine config directory", "STORAGE_ERROR");

    std::string path = dir + "/license.dat";
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return Error("No license file found", "LICENSE_NOT_FOUND");
    }

    std::string encrypted(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());
    in.close();

    std::string key = HardwareFingerprint::generate();
    std::string payload = xor_obfuscate(encrypted, key);

    json j = parse_json_safe(payload);
    if (j.contains("error")) {
        return Error("Corrupt or tampered license file", "STORAGE_CORRUPT");
    }
    return json_to_license(j);
}

Result<bool> LicenseManager::delete_license() {
    std::string dir = get_config_dir();
    if (dir.empty()) return Error("Cannot determine config directory", "STORAGE_ERROR");

    std::string path = dir + "/license.dat";
    if (std::remove(path.c_str()) != 0) {
        // Not an error if file doesn't exist
        std::ifstream check(path);
        if (check.good()) {
            return Error("Failed to delete license file", "STORAGE_ERROR");
        }
    }
    return true;
}

#elif defined(_WIN32)
// Windows: DPAPI-protected file

Result<bool> LicenseManager::store_license(const LicenseInfo& info) {
    std::string dir = get_appdata_dir();
    if (dir.empty()) return Error("Cannot determine AppData directory", "STORAGE_ERROR");

    CreateDirectoryA(dir.c_str(), nullptr);

    std::string payload = license_to_json(info).dump();

    DATA_BLOB input;
    input.pbData = reinterpret_cast<BYTE*>(payload.data());
    input.cbData = static_cast<DWORD>(payload.size());

    DATA_BLOB output;
    if (!CryptProtectData(&input, L"ShieldTier License", nullptr, nullptr,
                          nullptr, 0, &output)) {
        return Error("DPAPI encryption failed", "DPAPI_ERROR");
    }

    std::string path = dir + "\\license.dat";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        LocalFree(output.pbData);
        return Error("Failed to write license file", "STORAGE_ERROR");
    }
    out.write(reinterpret_cast<const char*>(output.pbData),
              static_cast<std::streamsize>(output.cbData));
    out.close();
    LocalFree(output.pbData);

    return true;
}

Result<LicenseInfo> LicenseManager::load_license() {
    std::string dir = get_appdata_dir();
    if (dir.empty()) return Error("Cannot determine AppData directory", "STORAGE_ERROR");

    std::string path = dir + "\\license.dat";
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return Error("No license file found", "LICENSE_NOT_FOUND");
    }

    std::string encrypted(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());
    in.close();

    DATA_BLOB input;
    input.pbData = reinterpret_cast<BYTE*>(encrypted.data());
    input.cbData = static_cast<DWORD>(encrypted.size());

    DATA_BLOB output;
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
        return Error("DPAPI decryption failed — possible machine mismatch", "DPAPI_ERROR");
    }

    std::string payload(reinterpret_cast<const char*>(output.pbData),
                        static_cast<size_t>(output.cbData));
    LocalFree(output.pbData);

    json j = parse_json_safe(payload);
    if (j.contains("error")) {
        return Error("Corrupt license data", "STORAGE_CORRUPT");
    }
    return json_to_license(j);
}

Result<bool> LicenseManager::delete_license() {
    std::string dir = get_appdata_dir();
    if (dir.empty()) return Error("Cannot determine AppData directory", "STORAGE_ERROR");

    std::string path = dir + "\\license.dat";
    if (!DeleteFileA(path.c_str())) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            return Error("Failed to delete license file", "STORAGE_ERROR");
        }
    }
    return true;
}

#else
// Unsupported platform — stub implementations

Result<bool> LicenseManager::store_license(const LicenseInfo&) {
    return Error("License storage not supported on this platform", "UNSUPPORTED_PLATFORM");
}

Result<LicenseInfo> LicenseManager::load_license() {
    return Error("License storage not supported on this platform", "UNSUPPORTED_PLATFORM");
}

Result<bool> LicenseManager::delete_license() {
    return Error("License storage not supported on this platform", "UNSUPPORTED_PLATFORM");
}

#endif

}  // namespace shieldtier
