---
name: Vault
description: Use when building infrastructure services — E2E encrypted chat (libsodium ShieldCrypt), authentication (JWT/bcrypt), atomic JSON config store, report export (HTML/JSON/ZIP), and network policy enforcement
---

# S9 — Vault: Chat, Auth, Config & Export

## Overview

Port V1's infrastructure subsystems to C++. E2E encrypted chat via libsodium (ShieldCrypt protocol), JWT authentication, encrypted atomic config store, multi-format report export, and network policy enforcement.

## Dependencies

- **Requires:** S0 (foundation) — libsodium, libcurl, nlohmann/json
- **No blocking dependencies** — fully parallel with S3-S8

## File Ownership

```
src/native/chat/
  manager.cpp/.h       (chat session lifecycle)
  shieldcrypt.cpp/.h   (E2E encryption — libsodium X25519 + XSalsa20-Poly1305)
  network.cpp/.h       (WebSocket client for chat relay)
  message_store.cpp/.h (local encrypted message storage)

src/native/auth/
  manager.cpp/.h       (auth flow — login, token refresh, tier validation)
  types.h              (JWT, auth tokens, user profile)

src/native/config/
  store.cpp/.h         (atomic JSON config with AES-256-GCM encryption)

src/native/export/
  manager.cpp/.h       (export orchestrator)
  html_template.cpp/.h (HTML report generation with embedded CSS)
  json_export.cpp/.h   (structured JSON export)
  zip_builder.cpp/.h   (ZIP package with report + artifacts)
  defang.cpp/.h        (URL/IP defanging for safe reporting)

src/native/network/
  policy.cpp/.h        (VPN detection, network policy enforcement)
```

## Exit Criteria

Encrypted config read/write. HTML/JSON/ZIP report generation from analysis results. E2E encrypted chat with forward secrecy. JWT-based auth with tier validation.

---

## ShieldCrypt (E2E Encrypted Chat)

```cpp
#include <sodium.h>

class ShieldCrypt {
public:
    struct KeyPair {
        uint8_t public_key[crypto_box_PUBLICKEYBYTES];   // 32 bytes
        uint8_t secret_key[crypto_box_SECRETKEYBYTES];    // 32 bytes
    };

    // Generate X25519 key pair
    static KeyPair generate_keypair() {
        KeyPair kp;
        crypto_box_keypair(kp.public_key, kp.secret_key);
        return kp;
    }

    // Encrypt message for recipient (X25519 + XSalsa20-Poly1305)
    static std::vector<uint8_t> encrypt(
        const std::string& plaintext,
        const uint8_t recipient_public[crypto_box_PUBLICKEYBYTES],
        const uint8_t sender_secret[crypto_box_SECRETKEYBYTES]) {

        uint8_t nonce[crypto_box_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        std::vector<uint8_t> ciphertext(
            crypto_box_NONCEBYTES + crypto_box_MACBYTES + plaintext.size());

        // Copy nonce to beginning
        memcpy(ciphertext.data(), nonce, crypto_box_NONCEBYTES);

        // Encrypt
        crypto_box_easy(
            ciphertext.data() + crypto_box_NONCEBYTES,
            reinterpret_cast<const uint8_t*>(plaintext.data()),
            plaintext.size(),
            nonce,
            recipient_public,
            sender_secret);

        return ciphertext;
    }

    // Decrypt message from sender
    static std::optional<std::string> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const uint8_t sender_public[crypto_box_PUBLICKEYBYTES],
        const uint8_t recipient_secret[crypto_box_SECRETKEYBYTES]) {

        if (ciphertext.size() < crypto_box_NONCEBYTES + crypto_box_MACBYTES)
            return std::nullopt;

        const uint8_t* nonce = ciphertext.data();
        const uint8_t* encrypted = ciphertext.data() + crypto_box_NONCEBYTES;
        size_t encrypted_len = ciphertext.size() - crypto_box_NONCEBYTES;

        std::vector<uint8_t> plaintext(encrypted_len - crypto_box_MACBYTES);

        if (crypto_box_open_easy(
                plaintext.data(), encrypted, encrypted_len,
                nonce, sender_public, recipient_secret) != 0) {
            return std::nullopt;  // decryption failed / tampered
        }

        return std::string(plaintext.begin(), plaintext.end());
    }
};
```

### Forward Secrecy (Ephemeral Keys)

```cpp
// For each chat session, generate ephemeral X25519 keys
// Exchange ephemerals, derive shared session key via X25519 + HKDF
// Messages encrypted with session key (XSalsa20-Poly1305)
// Session key destroyed on disconnect → past messages unrecoverable

struct ChatSession {
    uint8_t session_key[crypto_secretbox_KEYBYTES];  // derived from X25519

    std::vector<uint8_t> encrypt_message(const std::string& msg) {
        uint8_t nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        std::vector<uint8_t> out(crypto_secretbox_NONCEBYTES +
                                  crypto_secretbox_MACBYTES + msg.size());
        memcpy(out.data(), nonce, crypto_secretbox_NONCEBYTES);

        crypto_secretbox_easy(
            out.data() + crypto_secretbox_NONCEBYTES,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(), nonce, session_key);

        return out;
    }

    ~ChatSession() {
        sodium_memzero(session_key, sizeof(session_key));
    }
};
```

## Atomic Config Store

```cpp
class ConfigStore {
    std::string config_path_;
    uint8_t encryption_key_[32];  // from platform keychain (S11)
    std::shared_mutex mutex_;
    nlohmann::json config_;

public:
    // Load config from encrypted file
    bool load() {
        std::unique_lock lock(mutex_);
        auto data = read_file(config_path_);
        if (data.empty()) {
            config_ = default_config();
            return true;
        }

        // Decrypt: first 12 bytes = nonce, next 16 = tag, rest = ciphertext
        if (data.size() < crypto_aead_aes256gcm_NPUBBYTES +
                           crypto_aead_aes256gcm_ABYTES)
            return false;

        std::vector<uint8_t> plaintext(
            data.size() - crypto_aead_aes256gcm_NPUBBYTES -
            crypto_aead_aes256gcm_ABYTES);
        unsigned long long plaintext_len;

        if (crypto_aead_aes256gcm_decrypt(
                plaintext.data(), &plaintext_len,
                nullptr,
                data.data() + crypto_aead_aes256gcm_NPUBBYTES,
                data.size() - crypto_aead_aes256gcm_NPUBBYTES,
                nullptr, 0,
                data.data(),  // nonce
                encryption_key_) != 0) {
            return false;
        }

        config_ = nlohmann::json::parse(
            plaintext.begin(), plaintext.begin() + plaintext_len);
        return true;
    }

    // Save config with atomic write (write to temp, rename)
    bool save() {
        std::shared_lock lock(mutex_);
        auto plaintext = config_.dump();

        uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        std::vector<uint8_t> out(
            sizeof(nonce) + plaintext.size() + crypto_aead_aes256gcm_ABYTES);
        memcpy(out.data(), nonce, sizeof(nonce));

        unsigned long long ciphertext_len;
        crypto_aead_aes256gcm_encrypt(
            out.data() + sizeof(nonce), &ciphertext_len,
            reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
            nullptr, 0, nullptr,
            nonce, encryption_key_);

        // Atomic write: write to .tmp, then rename
        auto tmp_path = config_path_ + ".tmp";
        write_file(tmp_path, out);
        std::filesystem::rename(tmp_path, config_path_);
        return true;
    }

    // Thread-safe get/set
    nlohmann::json get(const std::string& key) {
        std::shared_lock lock(mutex_);
        return config_.value(key, nlohmann::json{});
    }

    void set(const std::string& key, const nlohmann::json& value) {
        std::unique_lock lock(mutex_);
        config_[key] = value;
        // Auto-save on write
        save();
    }
};
```

## Report Export

### HTML Template

```cpp
class HtmlExporter {
public:
    std::string generate(const ThreatVerdict& verdict,
                          const std::vector<AnalysisEngineResult>& results,
                          const FileBuffer& file) {
        std::string html = R"(<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>ShieldTier Analysis Report</title>
<style>)" + embedded_css() + R"(</style>
</head><body>
<div class="report">
<h1>Threat Analysis Report</h1>
<div class="verdict )" + verdict.risk_level + R"(">
  <h2>Verdict: )" + verdict_string(verdict.verdict) + R"(</h2>
  <p>Threat Score: )" + std::to_string(verdict.threat_score) + R"(/100</p>
  <p>Confidence: )" + std::to_string(int(verdict.confidence * 100)) + R"(%</p>
</div>

<h2>File Information</h2>
<table>
  <tr><td>Filename</td><td>)" + defang_filename(file.filename) + R"(</td></tr>
  <tr><td>SHA-256</td><td>)" + file.sha256 + R"(</td></tr>
  <tr><td>Size</td><td>)" + format_size(file.size()) + R"(</td></tr>
  <tr><td>MIME Type</td><td>)" + file.mime_type + R"(</td></tr>
</table>
)";
        // Add findings sections per engine...
        // Add MITRE ATT&CK mappings...
        html += "</div></body></html>";
        return html;
    }
};
```

### URL/IP Defanging

```cpp
namespace defang {

std::string url(const std::string& u) {
    std::string result = u;
    // http:// → hxxp://
    size_t pos = result.find("http://");
    if (pos != std::string::npos) result.replace(pos, 7, "hxxp://");
    pos = result.find("https://");
    if (pos != std::string::npos) result.replace(pos, 8, "hxxps://");
    // Defang dots in domain
    // example.com → example[.]com
    return result;
}

std::string ip(const std::string& ip_addr) {
    // 192.168.1.1 → 192[.]168[.]1[.]1
    std::string result;
    for (char c : ip_addr) {
        if (c == '.') result += "[.]";
        else result += c;
    }
    return result;
}

} // namespace defang
```

### ZIP Builder

```cpp
#include <archive.h>
#include <archive_entry.h>

class ZipBuilder {
    struct archive* a_;

public:
    ZipBuilder(const std::string& output_path) {
        a_ = archive_write_new();
        archive_write_set_format_zip(a_);
        archive_write_open_filename(a_, output_path.c_str());
    }

    void add_file(const std::string& name, const std::string& content) {
        struct archive_entry* entry = archive_entry_new();
        archive_entry_set_pathname(entry, name.c_str());
        archive_entry_set_size(entry, content.size());
        archive_entry_set_filetype(entry, AE_IFREG);
        archive_entry_set_perm(entry, 0644);

        archive_write_header(a_, entry);
        archive_write_data(a_, content.data(), content.size());
        archive_entry_free(entry);
    }

    void add_binary(const std::string& name, const uint8_t* data, size_t size) {
        struct archive_entry* entry = archive_entry_new();
        archive_entry_set_pathname(entry, name.c_str());
        archive_entry_set_size(entry, size);
        archive_entry_set_filetype(entry, AE_IFREG);
        archive_entry_set_perm(entry, 0644);

        archive_write_header(a_, entry);
        archive_write_data(a_, data, size);
        archive_entry_free(entry);
    }

    ~ZipBuilder() {
        archive_write_close(a_);
        archive_write_free(a_);
    }
};

// Build complete export package
void export_report(const ThreatVerdict& verdict,
                    const std::vector<AnalysisEngineResult>& results,
                    const FileBuffer& file,
                    const std::string& output_path) {
    ZipBuilder zip(output_path);

    auto html = HtmlExporter().generate(verdict, results, file);
    zip.add_file("report.html", html);

    auto json = JsonExporter().generate(verdict, results, file);
    zip.add_file("report.json", json);

    // Add sample (password-protected in practice)
    zip.add_binary("sample/" + file.filename, file.ptr(), file.size());
}
```

## Auth Manager

```cpp
struct AuthToken {
    std::string access_token;   // JWT
    std::string refresh_token;
    int64_t expires_at;
    Tier tier;
};

class AuthManager {
    AuthToken current_token_;

public:
    Result<AuthToken> login(const std::string& license_key,
                             const std::string& machine_fingerprint) {
        auto resp = http::post(
            "https://api.shieldtier.com/auth/activate",
            {{"Content-Type", "application/json"}},
            nlohmann::json{
                {"license_key", license_key},
                {"fingerprint", machine_fingerprint}
            }.dump());

        if (resp.status_code != 200) return Error("Auth failed");

        auto data = nlohmann::json::parse(resp.body);
        current_token_ = {
            data["access_token"],
            data["refresh_token"],
            data["expires_at"],
            parse_tier(data["tier"])
        };
        return current_token_;
    }

    bool is_tier_allowed(Tier required) const {
        return static_cast<int>(current_token_.tier) >= static_cast<int>(required);
    }
};
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Not zeroing secret keys after use | Always sodium_memzero on keys, session data |
| Config write without atomic rename | Crash during write corrupts config — write to .tmp then rename |
| Hardcoding encryption key | Key must come from platform keychain (S11 provides) |
| Not defanging URLs/IPs in reports | Reports shared externally — always defang to prevent accidental clicks |
| JWT validation on client only | Server must validate JWT on every API call — client check is convenience |
| libsodium without sodium_init() | Call sodium_init() once at startup before any crypto operations |
| Chat keys in memory after session end | Zero all session keys in destructor |
| ZIP without password for malware samples | Exported samples must be password-protected |
