#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "common/result.h"

namespace shieldtier {

struct RuleSet {
    std::string name;
    std::string source;
    std::string origin;
};

class RuleManager {
public:
    RuleManager();

    Result<bool> load_from_directory(const std::string& path);
    Result<bool> add_rule(const std::string& name, const std::string& source,
                          const std::string& origin = "custom");
    std::vector<RuleSet> get_all_rules() const;
    size_t rule_count() const;

private:
    void load_builtin_rules();

    mutable std::mutex mutex_;
    std::vector<RuleSet> rules_;
};

}  // namespace shieldtier
