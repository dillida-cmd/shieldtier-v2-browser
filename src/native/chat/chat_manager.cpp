#include "chat/chat_manager.h"

#include <chrono>
#include <algorithm>
#include <filesystem>
#include <fstream>
#ifndef SHIELDTIER_NO_SODIUM
#include <sodium.h>
#endif

namespace shieldtier {

ChatManager::ChatManager(const std::string& storage_path)
    : storage_path_(storage_path) {
    // Ensure storage directory exists
    std::filesystem::create_directories(storage_path_);
    load_messages();
    load_contacts();
}

ChatManager::~ChatManager() {
    save_messages();
    save_contacts();
}

Result<bool> ChatManager::initialize_keys() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (initialized_) {
        return true;
    }

    auto init_result = ShieldCrypt::initialize();
    if (!init_result.ok()) {
        return Error{init_result.error().message, init_result.error().code};
    }

    auto kp_result = ShieldCrypt::generate_keypair();
    if (!kp_result.ok()) {
        return Error{kp_result.error().message, kp_result.error().code};
    }

    keypair_ = std::move(kp_result.value());
    initialized_ = true;
    return true;
}

std::vector<uint8_t> ChatManager::get_public_key() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return keypair_.public_key;
}

Result<EncryptedMessage> ChatManager::send_message(
    const std::string& plaintext,
    const std::vector<uint8_t>& recipient_pubkey) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!initialized_) {
        return Error{"chat manager not initialized", "NOT_INITIALIZED"};
    }

    auto result = ShieldCrypt::encrypt(plaintext, recipient_pubkey, keypair_.secret_key);
    if (!result.ok()) {
        return result;
    }

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    ChatMessage msg;
    msg.id = generate_message_id();
    msg.sender_id = "self";
    msg.content = plaintext;
    msg.timestamp = now;
    msg.is_encrypted = true;
    msg.read = true;
    history_.push_back(std::move(msg));

    return result;
}

Result<ChatMessage> ChatManager::receive_message(
    const EncryptedMessage& encrypted,
    const std::string& sender_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!initialized_) {
        return Error{"chat manager not initialized", "NOT_INITIALIZED"};
    }

    auto result = ShieldCrypt::decrypt(encrypted, keypair_.secret_key);
    if (!result.ok()) {
        return Error{result.error().message, result.error().code};
    }

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    ChatMessage msg;
    msg.id = generate_message_id();
    msg.sender_id = sender_id;
    msg.conversation_id = conversation_id_for(sender_id);
    msg.content = result.value();
    msg.timestamp = now;
    msg.is_encrypted = true;
    msg.read = false;
    history_.push_back(msg);

    return msg;
}

std::vector<ChatMessage> ChatManager::get_history(int limit) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (limit <= 0 || history_.empty()) {
        return {};
    }

    auto count = std::min(static_cast<size_t>(limit), history_.size());
    auto start = history_.end() - static_cast<ptrdiff_t>(count);
    return {start, history_.end()};
}

std::vector<ChatMessage> ChatManager::get_conversation_messages(
    const std::string& conversation_id, int limit, int64_t before) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ChatMessage> result;
    for (auto it = history_.rbegin(); it != history_.rend(); ++it) {
        if (before > 0 && it->timestamp >= before) continue;
        std::string cid = conversation_id_for(
            it->sender_id == "self" ? it->recipient_id : it->sender_id);
        if (cid == conversation_id) {
            result.push_back(*it);
            if (static_cast<int>(result.size()) >= limit) break;
        }
    }
    std::reverse(result.begin(), result.end());
    return result;
}

void ChatManager::clear_history() {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.clear();
    save_messages();
}

void ChatManager::save_messages() {
    try {
        json arr = json::array();
        for (const auto& msg : history_) {
            arr.push_back({
                {"id", msg.id},
                {"conversationId", msg.conversation_id},
                {"senderId", msg.sender_id},
                {"recipientId", msg.recipient_id},
                {"content", msg.content},
                {"timestamp", msg.timestamp},
                {"encrypted", msg.is_encrypted},
                {"read", msg.read},
            });
        }
        std::string path = storage_path_ + "/messages.json";
        std::ofstream out(path);
        if (out.is_open()) {
            out << arr.dump(2);
        }
    } catch (...) {}
}

void ChatManager::load_messages() {
    try {
        std::string path = storage_path_ + "/messages.json";
        std::ifstream in(path);
        if (!in.is_open()) return;
        json arr = json::parse(in);
        if (!arr.is_array()) return;
        for (const auto& j : arr) {
            ChatMessage msg;
            msg.id = j.value("id", "");
            msg.conversation_id = j.value("conversationId", "");
            msg.sender_id = j.value("senderId", "");
            msg.recipient_id = j.value("recipientId", "");
            msg.content = j.value("content", "");
            msg.timestamp = j.value("timestamp", int64_t(0));
            msg.is_encrypted = j.value("encrypted", false);
            msg.read = j.value("read", true);
            history_.push_back(std::move(msg));
        }
    } catch (...) {}
}

// ── Contact management ──

void ChatManager::add_contact(const ChatContact& contact) {
    std::lock_guard<std::mutex> lock(mutex_);
    contacts_[contact.id] = contact;
    // save_contacts called without lock — need to do it inline
    // (We'll call save externally or the destructor handles it)
}

void ChatManager::remove_contact(const std::string& contact_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    contacts_.erase(contact_id);
}

void ChatManager::approve_contact(const std::string& contact_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = contacts_.find(contact_id);
    if (it != contacts_.end()) {
        it->second.status = "approved";
    }
}

void ChatManager::reject_contact(const std::string& contact_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = contacts_.find(contact_id);
    if (it != contacts_.end()) {
        it->second.status = "rejected";
    }
}

void ChatManager::update_contact_name(const std::string& contact_id,
                                        const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = contacts_.find(contact_id);
    if (it != contacts_.end()) {
        it->second.display_name = name;
    }
}

std::vector<ChatContact> ChatManager::get_contacts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ChatContact> result;
    result.reserve(contacts_.size());
    for (const auto& [_, c] : contacts_) {
        result.push_back(c);
    }
    return result;
}

ChatContact* ChatManager::get_contact(const std::string& contact_id) {
    auto it = contacts_.find(contact_id);
    return (it != contacts_.end()) ? &it->second : nullptr;
}

void ChatManager::save_contacts() {
    try {
        json arr = json::array();
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [_, c] : contacts_) {
            arr.push_back({
                {"id", c.id},
                {"displayName", c.display_name},
                {"publicKey", c.public_key_b64},
                {"status", c.status},
                {"presence", c.presence},
                {"lastSeen", c.last_seen},
            });
        }
        std::string path = storage_path_ + "/contacts.json";
        std::ofstream out(path);
        if (out.is_open()) {
            out << arr.dump(2);
        }
    } catch (...) {}
}

void ChatManager::load_contacts() {
    try {
        std::string path = storage_path_ + "/contacts.json";
        std::ifstream in(path);
        if (!in.is_open()) return;
        json arr = json::parse(in);
        if (!arr.is_array()) return;
        for (const auto& j : arr) {
            ChatContact c;
            c.id = j.value("id", "");
            c.display_name = j.value("displayName", "");
            c.public_key_b64 = j.value("publicKey", "");
            c.status = j.value("status", "pending");
            c.presence = j.value("presence", "offline");
            c.last_seen = j.value("lastSeen", int64_t(0));
            if (!c.id.empty()) {
                contacts_[c.id] = std::move(c);
            }
        }
    } catch (...) {}
}

// ── Conversations ──

std::vector<ChatConversation> ChatManager::get_conversations() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<std::string, ChatConversation> convos;

    for (const auto& msg : history_) {
        std::string peer = (msg.sender_id == "self") ? msg.recipient_id : msg.sender_id;
        if (peer.empty() || peer == "self") continue;

        std::string cid = conversation_id_for(peer);
        auto& conv = convos[cid];
        if (conv.id.empty()) {
            conv.id = cid;
            conv.contact_id = peer;
        }
        if (msg.timestamp > conv.last_timestamp) {
            conv.last_message = msg.content;
            conv.last_timestamp = msg.timestamp;
        }
        if (!msg.read && msg.sender_id != "self") {
            conv.unread_count++;
        }
    }

    std::vector<ChatConversation> result;
    result.reserve(convos.size());
    for (auto& [_, c] : convos) {
        result.push_back(std::move(c));
    }
    // Sort by most recent
    std::sort(result.begin(), result.end(),
              [](const ChatConversation& a, const ChatConversation& b) {
                  return a.last_timestamp > b.last_timestamp;
              });
    return result;
}

void ChatManager::mark_conversation_read(const std::string& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& msg : history_) {
        std::string peer = (msg.sender_id == "self") ? msg.recipient_id : msg.sender_id;
        if (conversation_id_for(peer) == conversation_id) {
            msg.read = true;
        }
    }
}

// ── Presence ──

void ChatManager::set_presence(const std::string& status) {
    std::lock_guard<std::mutex> lock(mutex_);
    presence_ = status;
}

std::string ChatManager::get_presence() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return presence_;
}

void ChatManager::update_contact_presence(const std::string& contact_id,
                                            const std::string& presence) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = contacts_.find(contact_id);
    if (it != contacts_.end()) {
        it->second.presence = presence;
        it->second.last_seen = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
}

void ChatManager::store_message(ChatMessage msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (msg.id.empty()) msg.id = generate_message_id();
    if (msg.timestamp == 0) {
        msg.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    history_.push_back(std::move(msg));
}

std::string ChatManager::generate_message_id() {
    uint8_t buf[16];
#ifndef SHIELDTIER_NO_SODIUM
    randombytes_buf(buf, sizeof(buf));
#else
    for (auto& b : buf) b = static_cast<uint8_t>(rand() & 0xFF);
#endif

    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    for (auto byte : buf) {
        id.push_back(hex_chars[byte >> 4]);
        id.push_back(hex_chars[byte & 0x0f]);
    }
    return id;
}

std::string ChatManager::conversation_id_for(const std::string& peer_id) const {
    // Conversation ID is deterministic for a peer
    return "conv_" + peer_id;
}

}  // namespace shieldtier
