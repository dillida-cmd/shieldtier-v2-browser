#include "auth/auth_manager.h"

#include <chrono>
#include <cstddef>
#include <set>
#include <unordered_map>

#ifndef SHIELDTIER_NO_SODIUM
#include <sodium.h>
#endif

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
#ifndef SHIELDTIER_NO_SODIUM
    std::vector<uint8_t> buf(input.size());
    size_t decoded_len = 0;
    int rc = sodium_base642bin(
        buf.data(), buf.size(),
        input.c_str(), input.size(),
        nullptr, &decoded_len, nullptr,
        sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (rc != 0) return {};
    return std::string(reinterpret_cast<const char*>(buf.data()), decoded_len);
#else
    // Simple base64url decode without libsodium
    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    // Convert URL-safe to standard base64
    std::string b64 = input;
    for (auto& c : b64) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    while (b64.size() % 4) b64 += '=';

    std::string out;
    out.reserve(b64.size() * 3 / 4);
    for (size_t i = 0; i + 3 < b64.size(); i += 4) {
        int a = T[(unsigned char)b64[i]], b2 = T[(unsigned char)b64[i+1]];
        int c = T[(unsigned char)b64[i+2]], d = T[(unsigned char)b64[i+3]];
        if (a < 0 || b2 < 0) break;
        out += static_cast<char>((a << 2) | (b2 >> 4));
        if (c >= 0) out += static_cast<char>(((b2 & 0xF) << 4) | (c >> 2));
        if (d >= 0) out += static_cast<char>(((c & 0x3) << 6) | d);
    }
    return out;
#endif
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
