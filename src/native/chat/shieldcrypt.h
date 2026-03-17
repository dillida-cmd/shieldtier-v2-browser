#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "common/result.h"

namespace shieldtier {

struct KeyPair {
    std::vector<uint8_t> public_key;   // 32 bytes (X25519)
    std::vector<uint8_t> secret_key;   // 32 bytes (X25519)
};

struct EncryptedMessage {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;        // 24 bytes (crypto_box nonce)
    std::vector<uint8_t> sender_pubkey;
};

class ShieldCrypt {
public:
    static Result<bool> initialize();

    static Result<KeyPair> generate_keypair();
    static Result<EncryptedMessage> encrypt(
        const std::string& plaintext,
        const std::vector<uint8_t>& recipient_pubkey,
        const std::vector<uint8_t>& sender_secretkey);
    static Result<std::string> decrypt(
        const EncryptedMessage& message,
        const std::vector<uint8_t>& recipient_secretkey);

    static std::string encode_base64(const std::vector<uint8_t>& data);
    static Result<std::vector<uint8_t>> decode_base64(const std::string& b64);
};

}  // namespace shieldtier
