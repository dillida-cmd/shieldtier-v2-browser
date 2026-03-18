#pragma once

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "chat/shieldcrypt.h"
#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

struct ChatMessage {
    std::string id;
    std::string conversation_id;
    std::string sender_id;
    std::string recipient_id;
    std::string content;      // plaintext (decrypted)
    int64_t timestamp = 0;
    bool is_encrypted = false;
    bool read = false;
};

struct ChatContact {
    std::string id;             // session ID of the contact
    std::string display_name;
    std::string public_key_b64;
    std::string status;         // "pending", "approved", "rejected"
    std::string presence;       // "online", "offline", "away"
    int64_t last_seen = 0;
};

struct ChatConversation {
    std::string id;
    std::string contact_id;
    std::string last_message;
    int64_t last_timestamp = 0;
    int unread_count = 0;
};

class ChatManager {
public:
    explicit ChatManager(const std::string& storage_path);
    ~ChatManager();

    Result<bool> initialize_keys();
    std::vector<uint8_t> get_public_key() const;

    Result<EncryptedMessage> send_message(
        const std::string& plaintext,
        const std::vector<uint8_t>& recipient_pubkey);

    Result<ChatMessage> receive_message(
        const EncryptedMessage& encrypted,
        const std::string& sender_id);

    // Message persistence
    std::vector<ChatMessage> get_history(int limit = 100) const;
    std::vector<ChatMessage> get_conversation_messages(
        const std::string& conversation_id, int limit = 100,
        int64_t before = 0) const;
    void clear_history();
    void save_messages();
    void load_messages();

    // Contact management
    void add_contact(const ChatContact& contact);
    void remove_contact(const std::string& contact_id);
    void approve_contact(const std::string& contact_id);
    void reject_contact(const std::string& contact_id);
    void update_contact_name(const std::string& contact_id,
                              const std::string& name);
    std::vector<ChatContact> get_contacts() const;
    ChatContact* get_contact(const std::string& contact_id);
    void save_contacts();
    void load_contacts();

    // Conversations
    std::vector<ChatConversation> get_conversations() const;
    void mark_conversation_read(const std::string& conversation_id);

    // Presence
    void set_presence(const std::string& status);
    std::string get_presence() const;
    void update_contact_presence(const std::string& contact_id,
                                  const std::string& presence);

    // Store a local message (sent or received) with persistence
    void store_message(ChatMessage msg);

private:
    std::string generate_message_id();
    std::string conversation_id_for(const std::string& peer_id) const;

    KeyPair keypair_;
    std::vector<ChatMessage> history_;
    std::unordered_map<std::string, ChatContact> contacts_;
    std::string storage_path_;
    std::string presence_ = "online";
    mutable std::mutex mutex_;
    bool initialized_ = false;
};

}  // namespace shieldtier
