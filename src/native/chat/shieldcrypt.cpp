#include "chat/shieldcrypt.h"

#ifndef SHIELDTIER_NO_SODIUM
#include <sodium.h>
#endif

namespace shieldtier {

#ifdef SHIELDTIER_NO_SODIUM

// Stub implementations when libsodium is not available
Result<bool> ShieldCrypt::initialize() { return true; }
Result<KeyPair> ShieldCrypt::generate_keypair() {
    KeyPair kp;
    kp.public_key.resize(32, 0);
    kp.secret_key.resize(32, 0);
    // Fill with pseudo-random bytes using C++ random
    for (size_t i = 0; i < 32; ++i) {
        kp.public_key[i] = static_cast<uint8_t>(rand() & 0xFF);
        kp.secret_key[i] = static_cast<uint8_t>(rand() & 0xFF);
    }
    return kp;
}
Result<EncryptedMessage> ShieldCrypt::encrypt(
    const std::string& plaintext,
    const std::vector<uint8_t>& /*recipient_pubkey*/,
    const std::vector<uint8_t>& /*sender_secretkey*/) {
    EncryptedMessage msg;
    msg.ciphertext.assign(plaintext.begin(), plaintext.end());
    msg.nonce.resize(24, 0);
    msg.sender_pubkey.resize(32, 0);
    return msg;
}
Result<std::string> ShieldCrypt::decrypt(
    const EncryptedMessage& message,
    const std::vector<uint8_t>& /*recipient_secretkey*/) {
    return std::string(message.ciphertext.begin(), message.ciphertext.end());
}
std::string ShieldCrypt::encode_base64(const std::vector<uint8_t>& data) {
    static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    size_t i = 0;
    while (i < data.size()) {
        uint32_t a = i < data.size() ? data[i++] : 0;
        uint32_t b = i < data.size() ? data[i++] : 0;
        uint32_t c = i < data.size() ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        result += table[(triple >> 18) & 0x3F];
        result += table[(triple >> 12) & 0x3F];
        result += table[(triple >> 6) & 0x3F];
        result += table[triple & 0x3F];
    }
    return result;
}
Result<std::vector<uint8_t>> ShieldCrypt::decode_base64(const std::string& /*b64*/) {
    return std::vector<uint8_t>{};
}

#else  // libsodium available

Result<bool> ShieldCrypt::initialize() {
    if (sodium_init() == -1) {
        return Error{"sodium_init() failed", "SODIUM_INIT_FAILED"};
    }
    return true;
}

Result<KeyPair> ShieldCrypt::generate_keypair() {
    KeyPair kp;
    kp.public_key.resize(crypto_box_PUBLICKEYBYTES);
    kp.secret_key.resize(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(kp.public_key.data(), kp.secret_key.data());
    return kp;
}

Result<EncryptedMessage> ShieldCrypt::encrypt(
    const std::string& plaintext,
    const std::vector<uint8_t>& recipient_pubkey,
    const std::vector<uint8_t>& sender_secretkey) {
    if (recipient_pubkey.size() != crypto_box_PUBLICKEYBYTES) {
        return Error{"invalid recipient public key size", "INVALID_PUBKEY"};
    }
    if (sender_secretkey.size() != crypto_box_SECRETKEYBYTES) {
        return Error{"invalid sender secret key size", "INVALID_SECRETKEY"};
    }

    EncryptedMessage msg;

    msg.nonce.resize(crypto_box_NONCEBYTES);
    randombytes_buf(msg.nonce.data(), crypto_box_NONCEBYTES);

    msg.ciphertext.resize(plaintext.size() + crypto_box_MACBYTES);

    if (crypto_box_easy(
            msg.ciphertext.data(),
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            plaintext.size(),
            msg.nonce.data(),
            recipient_pubkey.data(),
            sender_secretkey.data()) != 0) {
        return Error{"encryption failed", "ENCRYPT_FAILED"};
    }

    // Derive sender public key from secret key so recipient can decrypt
    msg.sender_pubkey.resize(crypto_box_PUBLICKEYBYTES);
    crypto_scalarmult_base(msg.sender_pubkey.data(), sender_secretkey.data());

    return msg;
}

Result<std::string> ShieldCrypt::decrypt(
    const EncryptedMessage& message,
    const std::vector<uint8_t>& recipient_secretkey) {
    if (message.nonce.size() != crypto_box_NONCEBYTES) {
        return Error{"invalid nonce size", "INVALID_NONCE"};
    }
    if (message.sender_pubkey.size() != crypto_box_PUBLICKEYBYTES) {
        return Error{"invalid sender public key size", "INVALID_PUBKEY"};
    }
    if (recipient_secretkey.size() != crypto_box_SECRETKEYBYTES) {
        return Error{"invalid recipient secret key size", "INVALID_SECRETKEY"};
    }
    if (message.ciphertext.size() < crypto_box_MACBYTES) {
        return Error{"ciphertext too short", "INVALID_CIPHERTEXT"};
    }

    std::vector<uint8_t> plaintext(message.ciphertext.size() - crypto_box_MACBYTES);

    if (crypto_box_open_easy(
            plaintext.data(),
            message.ciphertext.data(),
            message.ciphertext.size(),
            message.nonce.data(),
            message.sender_pubkey.data(),
            recipient_secretkey.data()) != 0) {
        return Error{"decryption failed — MAC verification failure", "DECRYPT_FAILED"};
    }

    return std::string(plaintext.begin(), plaintext.end());
}

std::string ShieldCrypt::encode_base64(const std::vector<uint8_t>& data) {
    const size_t b64_maxlen = sodium_base64_encoded_len(
        data.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string encoded(b64_maxlen, '\0');
    sodium_bin2base64(
        encoded.data(), b64_maxlen,
        data.data(), data.size(),
        sodium_base64_VARIANT_ORIGINAL);
    // sodium_bin2base64 null-terminates; trim the trailing null
    encoded.resize(std::strlen(encoded.c_str()));
    return encoded;
}

Result<std::vector<uint8_t>> ShieldCrypt::decode_base64(const std::string& b64) {
    std::vector<uint8_t> bin(b64.size());
    size_t bin_len = 0;

    if (sodium_base642bin(
            bin.data(), bin.size(),
            b64.c_str(), b64.size(),
            nullptr, &bin_len, nullptr,
            sodium_base64_VARIANT_ORIGINAL) != 0) {
        return Error{"base64 decode failed", "BASE64_DECODE_FAILED"};
    }

    bin.resize(bin_len);
    return bin;
}

#endif  // SHIELDTIER_NO_SODIUM

}  // namespace shieldtier
