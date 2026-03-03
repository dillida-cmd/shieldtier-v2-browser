#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace shieldtier {

using json = nlohmann::json;

inline json parse_json_safe(const std::string& input) {
    try {
        return json::parse(input);
    } catch (const json::parse_error&) {
        return json{{"error", "invalid_json"}};
    }
}

}  // namespace shieldtier
