#pragma once

#include <mutex>
#include <string>
#include <vector>

namespace shieldtier {

struct PolicyRule {
    std::string pattern;
    bool allow;
    std::string category;
};

class NetworkPolicy {
public:
    NetworkPolicy();

    bool should_allow(const std::string& url) const;
    void add_rule(const PolicyRule& rule);
    void remove_rule(const std::string& pattern);
    void load_defaults();
    std::vector<PolicyRule> get_rules() const;

private:
    std::vector<PolicyRule> rules_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
