#pragma once

#include <string>
#include <vector>

#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

enum class AgentMessageType {
    kHeartbeat, kReady, kSampleReceived, kEvent, kComplete, kError
};

struct AgentMessage {
    AgentMessageType type;
    json payload;
    int64_t timestamp;
};

class VmProtocol {
public:
    static std::string serialize(const AgentMessage& msg);
    static Result<AgentMessage> deserialize(const std::string& line);

    static std::vector<AgentMessage> parse_stream(const std::string& data);

    static std::vector<json> extract_events(const std::vector<AgentMessage>& messages);
};

}  // namespace shieldtier
