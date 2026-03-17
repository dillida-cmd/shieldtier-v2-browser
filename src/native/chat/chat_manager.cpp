#include "chat/chat_manager.h"

#include <chrono>
#include <algorithm>
#ifndef SHIELDTIER_NO_SODIUM
#include <sodium.h>
#endif

namespace shieldtier {

ChatManager::ChatManager(const std::string& storage_path)
    : storage_path_(storage_path) {}

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
    msg.content = result.value();
    msg.timestamp = now;
    msg.is_encrypted = true;
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

void ChatManager::clear_history() {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.clear();
}

std::string ChatManager::generate_message_id() {
    uint8_t buf[16];
    randombytes_buf(buf, sizeof(buf));

    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    for (auto byte : buf) {
        id.push_back(hex_chars[byte >> 4]);
        id.push_back(hex_chars[byte & 0x0f]);
    }
    return id;
}

}  // namespace shieldtier
