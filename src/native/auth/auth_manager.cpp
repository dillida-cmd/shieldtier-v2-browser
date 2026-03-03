#include "auth/auth_manager.h"

#include <chrono>
#include <cstddef>
#include <set>
#include <unordered_map>

#include <sodium.h>

namespace shieldtier {

static const std::unordered_map<std::string, std::set<std::string>> kTierFeatures = {
    {"free", {"basic_analysis"}},
    {"pro", {"basic_analysis", "yara_premium", "sandbox", "email_analysis"}},
    {"team", {"basic_analysis", "yara_premium", "sandbox", "email_analysis",
              "collaboration", "threat_feeds"}},
    {"enterprise", {"basic_analysis", "yara_premium", "sandbox", "email_analysis",
                    "collaboration", "threat_feeds", "server_scoring",
                    "custom_rules", "vm_sandbox"}},
};

static std::string base64url_decode(const std::string& input) {
    std::vector<uint8_t> buf(input.size());
    size_t decoded_len = 0;
    int rc = sodium_base642bin(
        buf.data(), buf.size(),
        input.c_str(), input.size(),
        nullptr, &decoded_len, nullptr,
        sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (rc != 0) return {};
    return std::string(reinterpret_cast<const char*>(buf.data()), decoded_len);
}

bool AuthToken::is_expired() const {
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return epoch >= expires_at;
}

AuthManager::AuthManager()
    : current_token_{"", "", Tier::kFree, 0} {}

Result<AuthToken> AuthManager::validate_token(const std::string& jwt) {
    auto payload_result = decode_jwt_payload(jwt);
    if (!payload_result.ok()) {
        return Error(payload_result.error().message, payload_result.error().code);
    }

    const auto& payload = payload_result.value();

    AuthToken token;
    token.token = jwt;
    token.user_id = payload.value("sub", "");
    token.expires_at = payload.value("exp", int64_t{0});
    token.tier = tier_from_string(payload.value("tier", "free"));

    std::lock_guard<std::mutex> lock(mutex_);
    if (token.is_expired()) {
        return Error("Token has expired", "token_expired");
    }
    current_token_ = token;
    return token;
}

Tier AuthManager::current_tier() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_token_.tier;
}

bool AuthManager::is_authenticated() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !current_token_.token.empty() && !current_token_.is_expired();
}

void AuthManager::set_token(const AuthToken& token) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_token_ = token;
}

void AuthManager::clear_token() {
    std::lock_guard<std::mutex> lock(mutex_);
    current_token_ = {"", "", Tier::kFree, 0};
}

bool AuthManager::has_feature(const std::string& feature) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (current_token_.token.empty() || current_token_.is_expired()) return false;

    std::string tier_str;
    switch (current_token_.tier) {
        case Tier::kFree:       tier_str = "free"; break;
        case Tier::kPro:        tier_str = "pro"; break;
        case Tier::kTeam:       tier_str = "team"; break;
        case Tier::kEnterprise: tier_str = "enterprise"; break;
    }

    auto it = kTierFeatures.find(tier_str);
    if (it == kTierFeatures.end()) return false;
    return it->second.count(feature) > 0;
}

Result<json> AuthManager::decode_jwt_payload(const std::string& jwt) {
    size_t first_dot = jwt.find('.');
    if (first_dot == std::string::npos) {
        return Error("Invalid JWT format: no dots found", "jwt_invalid");
    }

    size_t second_dot = jwt.find('.', first_dot + 1);
    if (second_dot == std::string::npos) {
        return Error("Invalid JWT format: only one dot found", "jwt_invalid");
    }

    std::string payload_b64 = jwt.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string payload_json = base64url_decode(payload_b64);

    try {
        return json::parse(payload_json);
    } catch (const json::parse_error& e) {
        return Error(std::string("JWT payload parse error: ") + e.what(), "jwt_parse_error");
    }
}

Tier AuthManager::tier_from_string(const std::string& s) {
    if (s == "pro") return Tier::kPro;
    if (s == "team") return Tier::kTeam;
    if (s == "enterprise") return Tier::kEnterprise;
    return Tier::kFree;
}

}  // namespace shieldtier
