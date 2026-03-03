#pragma once

#include <mutex>
#include <string>

#include "common/json.h"
#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

struct AuthToken {
    std::string token;
    std::string user_id;
    Tier tier;
    int64_t expires_at;

    bool is_expired() const;
};

class AuthManager {
public:
    AuthManager();

    Result<AuthToken> validate_token(const std::string& jwt);
    Tier current_tier() const;
    bool is_authenticated() const;
    void set_token(const AuthToken& token);
    void clear_token();
    bool has_feature(const std::string& feature) const;

private:
    Result<json> decode_jwt_payload(const std::string& jwt);
    static Tier tier_from_string(const std::string& s);

    AuthToken current_token_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
