#include "chat/chat_poller.h"

#include <chrono>
#include <thread>

namespace shieldtier {

ChatPoller::ChatPoller(const std::string& relay_url)
    : relay_url_(relay_url) {
    http_.set_timeout(10);
    http_.set_user_agent("ShieldTier/2.0");
}

ChatPoller::~ChatPoller() {
    stop();
}

void ChatPoller::set_identity(const std::string& session_id,
                                const std::string& auth_token) {
    std::lock_guard<std::mutex> lock(mutex_);
    session_id_ = session_id;
    auth_token_ = auth_token;
}

void ChatPoller::set_message_callback(MessageCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_message_ = std::move(cb);
}

void ChatPoller::start(int interval_ms) {
    if (running_.exchange(true)) return;  // already running

    poll_thread_ = std::jthread([this, interval_ms](std::stop_token st) {
        poll_loop(interval_ms);
    });
}

void ChatPoller::stop() {
    running_.store(false);
    if (poll_thread_.joinable()) {
        poll_thread_.request_stop();
        poll_thread_.join();
    }
}

void ChatPoller::poll_loop(int interval_ms) {
    while (running_.load()) {
        std::string sid;
        std::string token;
        MessageCallback callback;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            sid = session_id_;
            token = auth_token_;
            callback = on_message_;
        }

        if (!sid.empty() && !relay_url_.empty()) {
            std::string url = relay_url_ + "/messages/" + sid;
            std::unordered_map<std::string, std::string> headers = {
                {"Accept", "application/json"},
            };
            if (!token.empty()) {
                headers["Authorization"] = "Bearer " + token;
            }

            auto result = http_.get(url, headers);
            if (result.ok() && callback) {
                try {
                    auto& resp = result.value();
                    if (resp.status_code == 200 && !resp.body.empty()) {
                        json messages = json::parse(resp.body);
                        if (messages.is_array()) {
                            for (const auto& msg : messages) {
                                callback(msg);
                            }
                        }
                    }
                } catch (...) {}
            }
        }

        // Sleep in small intervals so we can check stop flag
        auto end = std::chrono::steady_clock::now() +
                   std::chrono::milliseconds(interval_ms);
        while (running_.load() && std::chrono::steady_clock::now() < end) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

bool ChatPoller::post_message(const std::string& recipient_id,
                                const json& payload) {
    std::string sid;
    std::string token;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sid = session_id_;
        token = auth_token_;
    }

    if (relay_url_.empty() || sid.empty()) return false;

    std::string url = relay_url_ + "/messages";
    json body = {
        {"from", sid},
        {"to", recipient_id},
        {"payload", payload},
        {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()}
    };

    std::unordered_map<std::string, std::string> headers = {
        {"Accept", "application/json"},
    };
    if (!token.empty()) {
        headers["Authorization"] = "Bearer " + token;
    }

    auto result = http_.post_raw(url, body.dump(), headers);
    return result.ok() && result.value().status_code < 300;
}

bool ChatPoller::send_heartbeat(const std::string& status) {
    std::string sid;
    std::string token;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sid = session_id_;
        token = auth_token_;
    }

    if (relay_url_.empty() || sid.empty()) return false;

    std::string url = relay_url_ + "/presence";
    json body = {
        {"sessionId", sid},
        {"status", status},
        {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()}
    };

    std::unordered_map<std::string, std::string> headers = {
        {"Accept", "application/json"},
    };
    if (!token.empty()) {
        headers["Authorization"] = "Bearer " + token;
    }

    auto result = http_.post_raw(url, body.dump(), headers);
    return result.ok() && result.value().status_code < 300;
}

}  // namespace shieldtier
