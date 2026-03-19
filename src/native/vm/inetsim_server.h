#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

struct INetSimConfig {
    int dns_port = 53;       // standard DNS — sandbox DNS client requires this
    int http_port = 80;      // standard HTTP — malware connects to port 80
    int https_port = 443;    // standard HTTPS
    std::string bind_address = "0.0.0.0";  // all interfaces — sandbox reaches host via gateway
    std::string fake_dns_ip = "";  // empty = auto-detect host IP visible to sandbox
};

struct NetworkEvent {
    std::string protocol;  // "dns", "http", "https", "smtp"
    std::string detail;
    json metadata;
    int64_t timestamp;
};

class INetSimServer {
public:
    explicit INetSimServer(const INetSimConfig& config = {});
    ~INetSimServer();

    Result<bool> start();
    void stop();
    bool is_running() const;

    std::vector<NetworkEvent> get_events() const;
    void clear_events();

private:
    void dns_server_loop();
    void http_server_loop();

    void record_event(const NetworkEvent& event);

    INetSimConfig config_;
    std::atomic<bool> running_{false};
    std::vector<std::jthread> server_threads_;
    std::vector<NetworkEvent> events_;
    mutable std::mutex events_mutex_;
};

}  // namespace shieldtier
