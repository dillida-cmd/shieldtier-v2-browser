#pragma once

#include <string>
#include <vector>

#include "common/types.h"

namespace shieldtier {

struct ImportPattern {
    std::string name;
    std::vector<std::string> required_apis;
    std::string mitre_id;
    std::string description;
    Severity severity;
};

struct StringPattern {
    std::string name;
    std::string pattern;
    std::string mitre_id;
    std::string description;
    Severity severity;
};

class BehaviorSignatures {
public:
    BehaviorSignatures();

    const std::vector<ImportPattern>& import_patterns() const;
    const std::vector<StringPattern>& string_patterns() const;

private:
    std::vector<ImportPattern> import_patterns_;
    std::vector<StringPattern> string_patterns_;
};

}  // namespace shieldtier
