#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "common/json.h"

namespace shieldtier {

class ChatPoller;

/// Tracks online/offline/away presence for chat contacts.
/// Matches V1's presence.ts — broadcasts heartbeats and tracks peer status.
class ChatPresence {
public:
    using PresenceCallback = std::function<void(const std::string& contact_id,
                                                  const std::string& status)>;

    explicit ChatPresence(ChatPoller* poller);
    ~ChatPresence();

    void set_callback(PresenceCallback cb);
    void set_own_status(const std::string& status);
    std::string get_own_status() const;

    /// Start sending heartbeats (typically every 30s).
    void start(int heartbeat_interval_ms = 30000);
    void stop();

    /// Called when a presence update is received from the relay.
    void on_presence_received(const std::string& contact_id,
                               const std::string& status);

    /// Get known presence for a contact.
    std::string get_contact_presence(const std::string& contact_id) const;

private:
    void heartbeat_loop(int interval_ms);

    ChatPoller* poller_;
    PresenceCallback callback_;
    std::string own_status_ = "online";
    std::unordered_map<std::string, std::string> contact_presence_;
    std::atomic<bool> running_{false};
    std::jthread heartbeat_thread_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
