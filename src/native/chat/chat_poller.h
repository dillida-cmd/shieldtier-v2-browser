#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "analysis/enrichment/http_client.h"
#include "common/json.h"

namespace shieldtier {

/// Polls a relay server for incoming chat messages.
/// Matches V1's poller.ts — periodic GET/POST to relay endpoint.
class ChatPoller {
public:
    using MessageCallback = std::function<void(const json& message)>;

    explicit ChatPoller(const std::string& relay_url);
    ~ChatPoller();

    void set_identity(const std::string& session_id,
                       const std::string& auth_token);
    void set_message_callback(MessageCallback cb);

    void start(int interval_ms = 5000);
    void stop();
    bool is_running() const { return running_.load(); }

    /// Post a message to the relay for delivery.
    bool post_message(const std::string& recipient_id, const json& payload);

    /// Send presence heartbeat to relay.
    bool send_heartbeat(const std::string& status);

private:
    void poll_loop(int interval_ms);

    std::string relay_url_;
    std::string session_id_;
    std::string auth_token_;
    MessageCallback on_message_;
    HttpClient http_;
    std::atomic<bool> running_{false};
    std::jthread poll_thread_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
