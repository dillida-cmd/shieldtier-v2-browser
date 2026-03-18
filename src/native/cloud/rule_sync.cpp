#include "cloud/rule_sync.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <unordered_set>

#ifndef SHIELDTIER_NO_SODIUM
#include <sodium.h>
#endif

#include "analysis/enrichment/http_client.h"

namespace shieldtier {
namespace fs = std::filesystem;

RuleSync::RuleSync(const RuleSyncConfig& config) : config_(config) {
    http_ = std::make_unique<HttpClient>();
    http_->set_timeout(60);

    std::error_code ec;
    fs::create_directories(config_.cache_dir, ec);

    decryption_key_ = RuleCrypto::derive_key(
        config_.license_key, config_.hardware_fingerprint);

    auto manifest_result = load_cached_manifest();
    if (manifest_result.ok()) {
        current_manifest_ = std::move(manifest_result.value());
    }
}

RuleSync::~RuleSync() = default;

void RuleSync::set_sync_callback(SyncCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(cb);
}

Result<int> RuleSync::sync() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (callback_) callback_("fetching_manifest", 0);

    auto manifest_result = fetch_manifest();
    if (!manifest_result.ok()) return manifest_result.error();

    auto server_manifest = std::move(manifest_result.value());

    // Determine delta — package IDs present on server but not cached locally
    std::vector<std::string> to_download;
    for (const auto& pid : server_manifest.package_ids) {
        if (!is_cached(pid)) {
            to_download.push_back(pid);
        }
    }

    if (callback_) {
        callback_("downloading",
                  to_download.empty() ? 100 : 10);
    }

    int synced = 0;
    int total = static_cast<int>(to_download.size());

    for (int i = 0; i < total; ++i) {
        const auto& pid = to_download[i];

        if (callback_) {
            int progress = 10 + (80 * (i + 1)) / std::max(total, 1);
            callback_("downloading_package", progress);
        }

        auto pkg_result = download_package(pid);
        if (!pkg_result.ok()) continue;

        auto decrypt_result = decrypt_package(pkg_result.value());
        if (!decrypt_result.ok()) continue;

        auto save_result = save_to_cache(pid, decrypt_result.value());
        if (save_result.ok() && save_result.value()) {
            ++synced;
        }
    }

    current_manifest_ = server_manifest;
    save_manifest(current_manifest_);
    prune_expired_cache();

    if (callback_) callback_("complete", 100);

    return synced;
}

Result<std::vector<uint8_t>> RuleSync::get_rules() {
    std::unique_lock<std::mutex> lock(mutex_);

    if (!has_valid_cache()) {
        lock.unlock();
        auto sync_result = sync();
        lock.lock();
        if (!sync_result.ok()) return sync_result.error();
    }

    std::vector<uint8_t> combined;

    for (const auto& pid : current_manifest_.package_ids) {
        auto data = load_from_cache(pid);
        if (!data.ok()) continue;

        const auto& bytes = data.value();
        if (!combined.empty()) {
            combined.push_back('\n');
        }
        combined.insert(combined.end(), bytes.begin(), bytes.end());
    }

    if (combined.empty()) {
        return Error("No cached rules available", "NO_RULES");
    }

    return combined;
}

bool RuleSync::has_valid_cache() const {
    if (current_manifest_.package_ids.empty()) return false;

    for (const auto& pid : current_manifest_.package_ids) {
        if (!is_cached(pid)) return false;
    }

    return true;
}

std::string RuleSync::current_version() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_manifest_.version;
}

Result<int> RuleSync::force_sync() {
    {
        std::lock_guard<std::mutex> lock(mutex_);

        std::error_code ec;
        for (auto& entry : fs::directory_iterator(config_.cache_dir, ec)) {
            fs::remove(entry.path(), ec);
        }

        current_manifest_ = RuleManifest{};
    }

    return sync();
}

Result<RuleManifest> RuleSync::fetch_manifest() {
    std::string url = config_.api_base_url + "/rules/manifest";
    auto result = http_->get_json(url, auth_headers());
    if (!result.ok()) return result.error();

    const auto& data = result.value();

    try {
        RuleManifest manifest;
        manifest.version = data.at("version").get<std::string>();
        manifest.timestamp = data.at("timestamp").get<int64_t>();
        manifest.checksum = data.at("checksum").get<std::string>();

        for (const auto& pid : data.at("package_ids")) {
            manifest.package_ids.push_back(pid.get<std::string>());
        }

        return manifest;
    } catch (const json::exception& e) {
        return Error(
            std::string("Failed to parse manifest: ") + e.what(),
            "MANIFEST_PARSE");
    }
}

Result<EncryptedRulePackage> RuleSync::download_package(
    const std::string& package_id) {
    std::string url =
        config_.api_base_url + "/rules/packages/" + package_id;
    auto result = http_->get_json(url, auth_headers());
    if (!result.ok()) return result.error();

    const auto& data = result.value();

    try {
        EncryptedRulePackage pkg;
        pkg.package_id = package_id;
        pkg.created_at = data.at("created_at").get<int64_t>();
        pkg.expires_at = data.at("expires_at").get<int64_t>();

        // Base64-decode ciphertext, nonce, tag from JSON
        auto decode_b64 = [](const std::string& encoded)
            -> Result<std::vector<uint8_t>> {
#ifdef SHIELDTIER_NO_SODIUM
            // Simple base64 decode without libsodium
            static const std::string b64chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::vector<uint8_t> out;
            out.reserve(encoded.size() * 3 / 4);
            int val = 0, valb = -8;
            for (unsigned char c : encoded) {
                if (c == '=' || c == '\n' || c == '\r') continue;
                auto pos = b64chars.find(c);
                if (pos == std::string::npos)
                    return Error("Base64 decode failed", "B64_DECODE");
                val = (val << 6) + static_cast<int>(pos);
                valb += 6;
                if (valb >= 0) {
                    out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
                    valb -= 8;
                }
            }
            return out;
#else
            size_t max_len = encoded.size();
            std::vector<uint8_t> out(max_len);
            size_t actual_len = 0;

            int rc = sodium_base642bin(
                out.data(), max_len,
                encoded.c_str(), encoded.size(),
                nullptr, &actual_len, nullptr,
                sodium_base64_VARIANT_ORIGINAL);

            if (rc != 0) {
                return Error("Base64 decode failed", "B64_DECODE");
            }

            out.resize(actual_len);
            return out;
#endif
        };

        auto ct = decode_b64(data.at("ciphertext").get<std::string>());
        if (!ct.ok()) return ct.error();
        pkg.ciphertext = std::move(ct.value());

        auto nonce = decode_b64(data.at("nonce").get<std::string>());
        if (!nonce.ok()) return nonce.error();
        pkg.nonce = std::move(nonce.value());

        auto tag = decode_b64(data.at("tag").get<std::string>());
        if (!tag.ok()) return tag.error();
        pkg.tag = std::move(tag.value());

        return pkg;
    } catch (const json::exception& e) {
        return Error(
            std::string("Failed to parse package: ") + e.what(),
            "PKG_PARSE");
    }
}

Result<std::vector<uint8_t>> RuleSync::decrypt_package(
    const EncryptedRulePackage& pkg) {
    return RuleCrypto::decrypt_package(pkg, decryption_key_);
}

Result<bool> RuleSync::save_to_cache(const std::string& package_id,
                                     const std::vector<uint8_t>& data) {
    fs::path path = fs::path(config_.cache_dir) / (package_id + ".rule");
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        return Error("Failed to open cache file for writing: " + path.string(),
                     "CACHE_WRITE");
    }

    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    if (!out.good()) {
        return Error("Failed to write cache file: " + path.string(),
                     "CACHE_WRITE");
    }

    return true;
}

Result<std::vector<uint8_t>> RuleSync::load_from_cache(
    const std::string& package_id) {
    fs::path path = fs::path(config_.cache_dir) / (package_id + ".rule");
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        return Error("Cache file not found: " + path.string(),
                     "CACHE_MISS");
    }

    auto file_size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(static_cast<size_t>(file_size));
    in.read(reinterpret_cast<char*>(data.data()),
            static_cast<std::streamsize>(file_size));

    if (!in.good() && !in.eof()) {
        return Error("Failed to read cache file: " + path.string(),
                     "CACHE_READ");
    }

    return data;
}

bool RuleSync::is_cached(const std::string& package_id) const {
    fs::path path = fs::path(config_.cache_dir) / (package_id + ".rule");
    return fs::exists(path);
}

void RuleSync::prune_expired_cache() {
    std::unordered_set<std::string> valid_ids(
        current_manifest_.package_ids.begin(),
        current_manifest_.package_ids.end());

    std::error_code ec;
    for (auto& entry : fs::directory_iterator(config_.cache_dir, ec)) {
        if (!entry.is_regular_file()) continue;

        auto stem = entry.path().stem().string();
        auto ext = entry.path().extension().string();

        // Keep manifest.json, only prune .rule files
        if (ext != ".rule") continue;

        if (valid_ids.find(stem) == valid_ids.end()) {
            fs::remove(entry.path(), ec);
        }
    }
}

Result<bool> RuleSync::save_manifest(const RuleManifest& manifest) {
    fs::path path = fs::path(config_.cache_dir) / "manifest.json";

    json j;
    j["version"] = manifest.version;
    j["timestamp"] = manifest.timestamp;
    j["package_ids"] = manifest.package_ids;
    j["checksum"] = manifest.checksum;

    std::ofstream out(path);
    if (!out) {
        return Error("Failed to open manifest for writing", "MANIFEST_WRITE");
    }

    out << j.dump(2);
    if (!out.good()) {
        return Error("Failed to write manifest", "MANIFEST_WRITE");
    }

    return true;
}

Result<RuleManifest> RuleSync::load_cached_manifest() {
    fs::path path = fs::path(config_.cache_dir) / "manifest.json";
    std::ifstream in(path);
    if (!in) {
        return Error("No cached manifest found", "NO_MANIFEST");
    }

    try {
        json j = json::parse(in);

        RuleManifest manifest;
        manifest.version = j.at("version").get<std::string>();
        manifest.timestamp = j.at("timestamp").get<int64_t>();
        manifest.checksum = j.at("checksum").get<std::string>();

        for (const auto& pid : j.at("package_ids")) {
            manifest.package_ids.push_back(pid.get<std::string>());
        }

        return manifest;
    } catch (const json::exception& e) {
        return Error(
            std::string("Failed to parse cached manifest: ") + e.what(),
            "MANIFEST_PARSE");
    }
}

std::unordered_map<std::string, std::string> RuleSync::auth_headers() const {
    return {
        {"Authorization", "Bearer " + config_.api_key},
        {"X-License-Key", config_.license_key},
        {"Accept", "application/json"},
    };
}

}  // namespace shieldtier
