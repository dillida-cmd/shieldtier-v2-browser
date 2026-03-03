#include "vm/inetsim_server.h"

#include <chrono>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif

namespace shieldtier {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void close_socket(socket_t sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

void set_socket_timeout(socket_t sock, int seconds) {
#ifdef _WIN32
    DWORD timeout_ms = seconds * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

bool set_reuse_addr(socket_t sock) {
    int opt = 1;
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                      reinterpret_cast<const char*>(&opt), sizeof(opt)) == 0;
}

// Extract domain name from DNS wire format question section starting at offset 12.
// Labels are length-prefixed: [len][chars][len][chars]...[0]
std::string parse_dns_name(const uint8_t* buf, size_t len, size_t offset) {
    std::string name;
    while (offset < len) {
        uint8_t label_len = buf[offset];
        if (label_len == 0) break;
        if (offset + 1 + label_len > len) break;
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(buf + offset + 1), label_len);
        offset += 1 + label_len;
    }
    return name;
}

// Build a minimal DNS A-record response for the given query
size_t build_dns_response(const uint8_t* query, size_t query_len,
                          uint8_t* resp, size_t resp_capacity,
                          uint32_t ip_addr) {
    if (query_len < 12 || resp_capacity < query_len + 16) return 0;

    std::memcpy(resp, query, query_len);

    // Set response flags: QR=1, AA=1, RD=1, RA=1, RCODE=0 -> 0x8580
    resp[2] = 0x85;
    resp[3] = 0x80;

    // ANCOUNT = 1
    resp[6] = 0x00;
    resp[7] = 0x01;

    size_t offset = query_len;

    // Answer: name pointer to question (0xC00C)
    resp[offset++] = 0xC0;
    resp[offset++] = 0x0C;

    // Type A (0x0001)
    resp[offset++] = 0x00;
    resp[offset++] = 0x01;

    // Class IN (0x0001)
    resp[offset++] = 0x00;
    resp[offset++] = 0x01;

    // TTL = 300
    resp[offset++] = 0x00;
    resp[offset++] = 0x00;
    resp[offset++] = 0x01;
    resp[offset++] = 0x2C;

    // RDLENGTH = 4
    resp[offset++] = 0x00;
    resp[offset++] = 0x04;

    // IP address in network byte order
    resp[offset++] = static_cast<uint8_t>((ip_addr >> 24) & 0xFF);
    resp[offset++] = static_cast<uint8_t>((ip_addr >> 16) & 0xFF);
    resp[offset++] = static_cast<uint8_t>((ip_addr >> 8) & 0xFF);
    resp[offset++] = static_cast<uint8_t>(ip_addr & 0xFF);

    return offset;
}

uint32_t parse_ipv4(const std::string& ip) {
    uint32_t result = 0;
    uint32_t octet = 0;
    int shift = 24;
    for (char c : ip) {
        if (c == '.') {
            result |= (octet & 0xFF) << shift;
            shift -= 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + static_cast<uint32_t>(c - '0');
        }
    }
    result |= (octet & 0xFF) << shift;
    return result;
}

// Extract the first line from an HTTP request (e.g. "GET /path HTTP/1.1")
// Returns {method, url}
std::pair<std::string, std::string> parse_http_request_line(const char* buf,
                                                            size_t len) {
    std::string line;
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] == '\r' || buf[i] == '\n') break;
        line += buf[i];
    }

    std::string method, url;
    size_t first_space = line.find(' ');
    if (first_space != std::string::npos) {
        method = line.substr(0, first_space);
        size_t second_space = line.find(' ', first_space + 1);
        if (second_space != std::string::npos) {
            url = line.substr(first_space + 1, second_space - first_space - 1);
        } else {
            url = line.substr(first_space + 1);
        }
    }
    return {method, url};
}

// Extract a brief snippet of headers (first 3 lines after request line)
std::string extract_headers_snippet(const char* buf, size_t len) {
    std::string snippet;
    int line_count = 0;
    bool past_first_line = false;
    size_t i = 0;

    while (i < len && line_count < 3) {
        if (buf[i] == '\n') {
            if (!past_first_line) {
                past_first_line = true;
            } else {
                ++line_count;
            }
        } else if (past_first_line && buf[i] != '\r') {
            snippet += buf[i];
            if (buf[i] == '\n' || (i + 1 < len && buf[i + 1] == '\r')) {
                snippet += "; ";
            }
        }
        ++i;
    }

    if (snippet.size() > 200) snippet.resize(200);
    return snippet;
}

constexpr const char* kHttpResponse =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Connection: close\r\n"
    "Server: INetSim/ShieldTier\r\n"
    "\r\n"
    "<!DOCTYPE html><html><head><title>INetSim</title></head>"
    "<body><h1>It works!</h1><p>INetSim fake HTTP server.</p></body></html>\r\n";

#ifdef _WIN32
void init_winsock() {
    static std::once_flag flag;
    std::call_once(flag, [] {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    });
}
#endif

}  // namespace

INetSimServer::INetSimServer(const INetSimConfig& config) : config_(config) {}

INetSimServer::~INetSimServer() {
    stop();
}

Result<bool> INetSimServer::start() {
    if (running_.load()) {
        return Error{"INetSim server already running", "ALREADY_RUNNING"};
    }

#ifdef _WIN32
    init_winsock();
#endif

    running_.store(true);

    server_threads_.emplace_back([this] { dns_server_loop(); });
    server_threads_.emplace_back([this] { http_server_loop(); });

    return true;
}

void INetSimServer::stop() {
    running_.store(false);
    server_threads_.clear();
}

bool INetSimServer::is_running() const {
    return running_.load();
}

std::vector<NetworkEvent> INetSimServer::get_events() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    return events_;
}

void INetSimServer::clear_events() {
    std::lock_guard<std::mutex> lock(events_mutex_);
    events_.clear();
}

void INetSimServer::record_event(const NetworkEvent& event) {
    std::lock_guard<std::mutex> lock(events_mutex_);
    events_.push_back(event);
}

void INetSimServer::dns_server_loop() {
    socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == kInvalidSocket) return;

    set_reuse_addr(sock);
    set_socket_timeout(sock, 1);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(config_.dns_port));
    inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr);

    if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(sock);
        return;
    }

    uint32_t fake_ip = parse_ipv4(config_.fake_dns_ip);

    uint8_t buf[512];
    uint8_t resp[1024];

    while (running_.load()) {
        struct sockaddr_in client_addr = {};
        socklen_t client_len = sizeof(client_addr);

        auto n = recvfrom(sock, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                          reinterpret_cast<struct sockaddr*>(&client_addr),
                          &client_len);

        if (n <= 0) continue;

        auto recv_len = static_cast<size_t>(n);
        if (recv_len < 12) continue;

        std::string domain = parse_dns_name(buf, recv_len, 12);

        // Determine query type from bytes after the question name
        std::string query_type = "A";
        size_t qname_end = 12;
        while (qname_end < recv_len && buf[qname_end] != 0) {
            qname_end += 1 + buf[qname_end];
        }
        if (qname_end + 3 < recv_len) {
            uint16_t qtype = (static_cast<uint16_t>(buf[qname_end + 1]) << 8) |
                             buf[qname_end + 2];
            switch (qtype) {
                case 1:  query_type = "A"; break;
                case 28: query_type = "AAAA"; break;
                case 5:  query_type = "CNAME"; break;
                case 15: query_type = "MX"; break;
                case 2:  query_type = "NS"; break;
                case 16: query_type = "TXT"; break;
                default: query_type = "TYPE" + std::to_string(qtype); break;
            }
        }

        size_t resp_len = build_dns_response(buf, recv_len, resp, sizeof(resp), fake_ip);
        if (resp_len > 0) {
            sendto(sock, reinterpret_cast<const char*>(resp), static_cast<int>(resp_len),
                   0, reinterpret_cast<struct sockaddr*>(&client_addr), client_len);
        }

        record_event(NetworkEvent{
            .protocol = "dns",
            .detail = domain,
            .metadata = json{
                {"query_type", query_type},
                {"response_ip", config_.fake_dns_ip}
            },
            .timestamp = now_ms()
        });
    }

    close_socket(sock);
}

void INetSimServer::http_server_loop() {
    socket_t listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == kInvalidSocket) return;

    set_reuse_addr(listen_sock);
    set_socket_timeout(listen_sock, 1);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(config_.http_port));
    inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr);

    if (bind(listen_sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(listen_sock);
        return;
    }

    if (listen(listen_sock, 16) != 0) {
        close_socket(listen_sock);
        return;
    }

    char buf[4096];

    while (running_.load()) {
        struct sockaddr_in client_addr = {};
        socklen_t client_len = sizeof(client_addr);

        socket_t client = accept(listen_sock,
                                 reinterpret_cast<struct sockaddr*>(&client_addr),
                                 &client_len);
        if (client == kInvalidSocket) continue;

        set_socket_timeout(client, 2);

        auto n = recv(client, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            auto [method, url] = parse_http_request_line(buf, static_cast<size_t>(n));
            std::string headers_snippet = extract_headers_snippet(buf, static_cast<size_t>(n));

            size_t resp_len = std::strlen(kHttpResponse);
            send(client, kHttpResponse, static_cast<int>(resp_len), 0);

            record_event(NetworkEvent{
                .protocol = "http",
                .detail = url,
                .metadata = json{
                    {"method", method},
                    {"headers_snippet", headers_snippet}
                },
                .timestamp = now_ms()
            });
        }

        close_socket(client);
    }

    close_socket(listen_sock);
}

}  // namespace shieldtier
