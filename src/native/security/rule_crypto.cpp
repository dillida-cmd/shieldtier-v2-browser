#include "security/rule_crypto.h"

#include <chrono>
#include <cstring>

#ifndef SHIELDTIER_NO_SODIUM
#include <sodium.h>
#endif

namespace shieldtier {

std::vector<uint8_t> RuleCrypto::derive_key(
    const std::string& license_key,
    const std::string& hardware_fingerprint) {
#ifdef SHIELDTIER_NO_SODIUM
    // Stub: return a deterministic 32-byte key from inputs
    std::vector<uint8_t> key(32, 0);
    for (size_t i = 0; i < license_key.size(); ++i)
        key[i % 32] ^= static_cast<uint8_t>(license_key[i]);
    for (size_t i = 0; i < hardware_fingerprint.size(); ++i)
        key[i % 32] ^= static_cast<uint8_t>(hardware_fingerprint[i]);
    return key;
#else
    std::vector<uint8_t> key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    // Use BLAKE2b keyed hash: message = license_key, key = hardware_fingerprint
    // If hardware_fingerprint is longer than BLAKE2b max key size, hash it first
    std::vector<uint8_t> hash_key;
    if (hardware_fingerprint.size() > crypto_generichash_KEYBYTES_MAX) {
        hash_key.resize(crypto_generichash_KEYBYTES);
        crypto_generichash(
            hash_key.data(), hash_key.size(),
            reinterpret_cast<const uint8_t*>(hardware_fingerprint.data()),
            hardware_fingerprint.size(),
            nullptr, 0);
    } else if (hardware_fingerprint.size() >= crypto_generichash_KEYBYTES_MIN) {
        hash_key.assign(
            reinterpret_cast<const uint8_t*>(hardware_fingerprint.data()),
            reinterpret_cast<const uint8_t*>(hardware_fingerprint.data()) +
                hardware_fingerprint.size());
    } else {
        // Pad short fingerprints to minimum key length
        hash_key.resize(crypto_generichash_KEYBYTES_MIN, 0);
        std::memcpy(hash_key.data(), hardware_fingerprint.data(),
                     hardware_fingerprint.size());
    }

    crypto_generichash(
        key.data(), key.size(),
        reinterpret_cast<const uint8_t*>(license_key.data()),
        license_key.size(),
        hash_key.data(), hash_key.size());

    return key;
#endif
}

Result<std::vector<uint8_t>> RuleCrypto::decrypt_package(
    const EncryptedRulePackage& package,
    const std::vector<uint8_t>& key) {

    if (is_expired(package)) {
        return Error("Rule package has expired", "RULE_EXPIRED");
    }

#ifdef SHIELDTIER_NO_SODIUM
    // Stub: cannot decrypt without libsodium
    (void)key;
    return Error("Decryption unavailable — libsodium not linked", "NO_SODIUM");
#else
    if (package.nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        return Error("Invalid nonce size", "INVALID_NONCE");
    }

    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        return Error("Invalid key size", "INVALID_KEY");
    }

    // For XChaCha20-Poly1305 IETF, the ciphertext includes the tag appended.
    // Build the combined ciphertext+tag buffer that libsodium expects.
    std::vector<uint8_t> combined;
    combined.reserve(package.ciphertext.size() + package.tag.size());
    combined.insert(combined.end(), package.ciphertext.begin(),
                    package.ciphertext.end());
    combined.insert(combined.end(), package.tag.begin(), package.tag.end());

    std::vector<uint8_t> plaintext(package.ciphertext.size());
    unsigned long long plaintext_len = 0;

    // Use package_id as additional data for binding
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &plaintext_len,
        nullptr,  // nsec (unused)
        combined.data(), combined.size(),
        reinterpret_cast<const uint8_t*>(package.package_id.data()),
        package.package_id.size(),
        package.nonce.data(),
        key.data());

    if (rc != 0) {
        return Error("Decryption failed — invalid key or tampered package",
                     "DECRYPT_FAILED");
    }

    plaintext.resize(static_cast<size_t>(plaintext_len));
    return plaintext;
#endif
}

bool RuleCrypto::is_expired(const EncryptedRulePackage& package) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    return now > package.expires_at;
}

}  // namespace shieldtier
