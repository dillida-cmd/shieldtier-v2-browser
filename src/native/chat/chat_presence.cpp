#include "chat/chat_presence.h"
#include "chat/chat_poller.h"

#include <chrono>
#include <thread>

namespace shieldtier {

ChatPresence::ChatPresence(ChatPoller* poller)
    : poller_(poller) {}

ChatPresence::~ChatPresence() {
    stop();
}

void ChatPresence::set_callback(PresenceCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(cb);
}

void ChatPresence::set_own_status(const std::string& status) {
    std::lock_guard<std::mutex> lock(mutex_);
    own_status_ = status;
}

std::string ChatPresence::get_own_status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return own_status_;
}

void ChatPresence::start(int heartbeat_interval_ms) {
    if (running_.exchange(true)) return;

    heartbeat_thread_ = std::jthread([this, heartbeat_interval_ms](std::stop_token) {
        heartbeat_loop(heartbeat_interval_ms);
    });
}

void ChatPresence::stop() {
    running_.store(false);
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.request_stop();
        heartbeat_thread_.join();
    }
}

void ChatPresence::on_presence_received(const std::string& contact_id,
                                          const std::string& status) {
    PresenceCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        contact_presence_[contact_id] = status;
        cb = callback_;
    }
    if (cb) {
        cb(contact_id, status);
    }
}

std::string ChatPresence::get_contact_presence(const std::string& contact_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = contact_presence_.find(contact_id);
    return (it != contact_presence_.end()) ? it->second : "offline";
}

void ChatPresence::heartbeat_loop(int interval_ms) {
    while (running_.load()) {
        std::string status;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            status = own_status_;
        }

        if (poller_) {
            poller_->send_heartbeat(status);
        }

        // Sleep in small intervals to allow stop
        auto end = std::chrono::steady_clock::now() +
                   std::chrono::milliseconds(interval_ms);
        while (running_.load() && std::chrono::steady_clock::now() < end) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    }
}

}  // namespace shieldtier
