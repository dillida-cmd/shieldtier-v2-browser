#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "common/result.h"

namespace shieldtier {

struct EncryptedRulePackage {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;   // 24 bytes for XChaCha20-Poly1305
    std::vector<uint8_t> tag;     // 16 bytes
    int64_t created_at;
    int64_t expires_at;           // 7-day TTL
    std::string package_id;
};

class RuleCrypto {
public:
    static std::vector<uint8_t> derive_key(
        const std::string& license_key,
        const std::string& hardware_fingerprint);

    static Result<std::vector<uint8_t>> decrypt_package(
        const EncryptedRulePackage& package,
        const std::vector<uint8_t>& key);

    static bool is_expired(const EncryptedRulePackage& package);
};

}  // namespace shieldtier
