#pragma once

#include <string>
#include <vector>

#include "common/json.h"
#include "common/types.h"

namespace shieldtier {

struct NormalizedEvent;

class LogNormalizer {
public:
    LogNormalizer();

    void normalize(std::vector<NormalizedEvent>& events);

private:
    void normalize_fields(NormalizedEvent& event);
    void extract_canonical_fields(NormalizedEvent& event);
    int64_t parse_timestamp(const std::string& ts);
    Severity map_severity(const std::string& level);
};

}  // namespace shieldtier
