#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "chat/shieldcrypt.h"
#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

struct ChatMessage {
    std::string id;
    std::string sender_id;
    std::string content;      // plaintext (decrypted)
    int64_t timestamp;
    bool is_encrypted;
};

class ChatManager {
public:
    explicit ChatManager(const std::string& storage_path);

    Result<bool> initialize_keys();
    std::vector<uint8_t> get_public_key() const;

    Result<EncryptedMessage> send_message(
        const std::string& plaintext,
        const std::vector<uint8_t>& recipient_pubkey);

    Result<ChatMessage> receive_message(
        const EncryptedMessage& encrypted,
        const std::string& sender_id);

    std::vector<ChatMessage> get_history(int limit = 100) const;
    void clear_history();

private:
    std::string generate_message_id();

    KeyPair keypair_;
    std::vector<ChatMessage> history_;
    std::string storage_path_;
    mutable std::mutex mutex_;
    bool initialized_ = false;
};

}  // namespace shieldtier
