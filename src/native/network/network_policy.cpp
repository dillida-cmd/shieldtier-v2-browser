#include "network/network_policy.h"

#include <algorithm>

namespace shieldtier {

NetworkPolicy::NetworkPolicy() = default;

bool NetworkPolicy::should_allow(const std::string& url) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& rule : rules_) {
        if (url.find(rule.pattern) != std::string::npos) {
            return rule.allow;
        }
    }

    return true;
}

void NetworkPolicy::add_rule(const PolicyRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back(rule);
}

void NetworkPolicy::remove_rule(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.erase(
        std::remove_if(rules_.begin(), rules_.end(),
                       [&](const PolicyRule& r) { return r.pattern == pattern; }),
        rules_.end());
}

void NetworkPolicy::load_defaults() {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.clear();

    // Malware C2 patterns
    rules_.push_back({".onion.", false, "malware"});
    rules_.push_back({"malware-c2.", false, "malware"});
    rules_.push_back({"cobaltstrike.", false, "malware"});
    rules_.push_back({".evil.", false, "malware"});
    rules_.push_back({"darkcomet.", false, "malware"});
    rules_.push_back({"njrat.", false, "malware"});
    rules_.push_back({"asyncrat.", false, "malware"});
    rules_.push_back({"quasarrat.", false, "malware"});

    // Ad trackers
    rules_.push_back({"doubleclick.net", false, "ads"});
    rules_.push_back({"googlesyndication.com", false, "ads"});
    rules_.push_back({"adnxs.com", false, "ads"});
    rules_.push_back({"adsrvr.org", false, "ads"});
    rules_.push_back({"adform.net", false, "ads"});

    // Tracking
    rules_.push_back({"google-analytics.com", false, "tracking"});
    rules_.push_back({"facebook.com/tr", false, "tracking"});
    rules_.push_back({"hotjar.com", false, "tracking"});
    rules_.push_back({"fullstory.com", false, "tracking"});
    rules_.push_back({"mixpanel.com", false, "tracking"});
}

std::vector<PolicyRule> NetworkPolicy::get_rules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_;
}

}  // namespace shieldtier
