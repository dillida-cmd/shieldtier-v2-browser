#include "network/network_policy.h"

#include <algorithm>
#include <cctype>

namespace shieldtier {

namespace {

std::string extract_host(const std::string& url) {
    size_t start = url.find("://");
    if (start == std::string::npos) return url;
    start += 3;
    size_t end = url.find_first_of(":/?\#", start);
    if (end == std::string::npos) return url.substr(start);
    return url.substr(start, end - start);
}

std::string to_lower(const std::string& s) {
    std::string result = s;
    for (auto& c : result) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return result;
}

/// DNS-over-HTTPS providers that must be blocked to prevent DNS exfiltration
/// and bypass of network monitoring. Matches V1's policy.ts DOH_HOSTS list.
static const char* kDoHProviders[] = {
    "dns.google",
    "dns.cloudflare.com",
    "cloudflare-dns.com",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard.com",
    "doh.cleanbrowsing.org",
    "dns.nextdns.io",
};

}  // namespace

NetworkPolicy::NetworkPolicy() = default;

bool NetworkPolicy::should_allow(const std::string& url) const {
    // Block STUN/TURN schemes (WebRTC leak prevention) — matches V1's policy
    if (is_stun_turn_scheme(url)) {
        return false;
    }

    std::string host = extract_host(url);
    std::string host_lower = to_lower(host);

    // Block localhost hostnames — matches V1's /localhost/i pattern
    if (is_localhost(host_lower)) {
        return false;
    }

    // Block DNS-over-HTTPS providers — prevents DNS bypass
    if (is_doh_provider(host_lower)) {
        return false;
    }

    // Check custom rules
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& rule : rules_) {
        if (host_lower.find(rule.pattern) != std::string::npos) {
            return rule.allow;
        }
    }

    return true;
}

// static
bool NetworkPolicy::is_doh_provider(const std::string& host) {
    for (const auto* provider : kDoHProviders) {
        if (host == provider || host.find(std::string(".") + provider) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// static
bool NetworkPolicy::is_stun_turn_scheme(const std::string& url) {
    std::string lower = to_lower(url);
    return lower.compare(0, 5, "stun:") == 0 ||
           lower.compare(0, 5, "turn:") == 0 ||
           lower.compare(0, 6, "stuns:") == 0 ||
           lower.compare(0, 6, "turns:") == 0;
}

// static
bool NetworkPolicy::is_localhost(const std::string& host) {
    return host == "localhost" ||
           host.find(".localhost") != std::string::npos;
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
