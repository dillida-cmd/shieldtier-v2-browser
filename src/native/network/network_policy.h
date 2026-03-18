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

    /// Returns true if the hostname is a known DNS-over-HTTPS provider.
    static bool is_doh_provider(const std::string& host);

    /// Returns true if the URL uses a STUN/TURN scheme.
    static bool is_stun_turn_scheme(const std::string& url);

    /// Returns true if the hostname resolves to localhost.
    static bool is_localhost(const std::string& host);

private:
    std::vector<PolicyRule> rules_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
