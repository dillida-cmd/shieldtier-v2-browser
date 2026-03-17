#include "vm/vm_protocol.h"

#include <sstream>

namespace shieldtier {

namespace {

std::string type_to_string(AgentMessageType type) {
    switch (type) {
        case AgentMessageType::kHeartbeat:      return "heartbeat";
        case AgentMessageType::kReady:          return "ready";
        case AgentMessageType::kSampleReceived: return "sample_received";
        case AgentMessageType::kEvent:          return "event";
        case AgentMessageType::kComplete:       return "complete";
        case AgentMessageType::kError:          return "error";
    }
    return "unknown";
}

Result<AgentMessageType> string_to_type(const std::string& s) {
    if (s == "heartbeat")       return AgentMessageType::kHeartbeat;
    if (s == "ready")           return AgentMessageType::kReady;
    if (s == "sample_received") return AgentMessageType::kSampleReceived;
    if (s == "event")           return AgentMessageType::kEvent;
    if (s == "complete")        return AgentMessageType::kComplete;
    if (s == "error")           return AgentMessageType::kError;
    return Error{"unknown agent message type: " + s, "UNKNOWN_TYPE"};
}

}  // namespace

std::string VmProtocol::serialize(const AgentMessage& msg) {
    json j;
    j["type"] = type_to_string(msg.type);
    j["payload"] = msg.payload;
    j["timestamp"] = msg.timestamp;
    return j.dump();
}

Result<AgentMessage> VmProtocol::deserialize(const std::string& line) {
    json j;
    try {
        j = json::parse(line);
    } catch (const json::parse_error& e) {
        return Error{"JSON parse error: " + std::string(e.what()), "PARSE_ERROR"};
    }

    if (!j.contains("type") || !j["type"].is_string()) {
        return Error{"missing or invalid 'type' field", "INVALID_MESSAGE"};
    }

    auto type_result = string_to_type(j["type"].get<std::string>());
    if (!type_result.ok()) {
        return Error{type_result.error().message, type_result.error().code};
    }

    AgentMessage msg;
    msg.type = type_result.value();
    msg.payload = j.value("payload", json::object());
    msg.timestamp = j.value("timestamp", int64_t{0});
    return msg;
}

std::vector<AgentMessage> VmProtocol::parse_stream(const std::string& data) {
    std::vector<AgentMessage> messages;
    std::istringstream stream(data);
    std::string line;

    while (std::getline(stream, line)) {
        if (line.empty()) continue;

        // Strip trailing \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) continue;

        auto result = deserialize(line);
        if (result.ok()) {
            messages.push_back(std::move(result.value()));
        }
    }

    return messages;
}

std::vector<json> VmProtocol::extract_events(
    const std::vector<AgentMessage>& messages) {
    std::vector<json> events;
    for (const auto& msg : messages) {
        if (msg.type == AgentMessageType::kEvent) {
            events.push_back(msg.payload);
        }
    }
    return events;
}

}  // namespace shieldtier
