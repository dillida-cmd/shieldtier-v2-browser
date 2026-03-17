#include <gtest/gtest.h>
#include "network/network_policy.h"

using namespace shieldtier;

TEST(NetworkPolicy, DefaultsLoaded) {
    NetworkPolicy policy;
    policy.load_defaults();
    auto rules = policy.get_rules();
    EXPECT_GT(rules.size(), 0u);
}

TEST(NetworkPolicy, BlockOnion) {
    NetworkPolicy policy;
    policy.load_defaults();
    EXPECT_FALSE(policy.should_allow("http://evil123.onion.to/page"));
}

TEST(NetworkPolicy, AllowNormal) {
    NetworkPolicy policy;
    policy.load_defaults();
    EXPECT_TRUE(policy.should_allow("https://www.google.com"));
}

TEST(NetworkPolicy, AddBlockRule) {
    NetworkPolicy policy;
    PolicyRule rule;
    rule.pattern = "blocked-domain.com";
    rule.allow = false;
    rule.category = "custom";
    policy.add_rule(rule);

    EXPECT_FALSE(policy.should_allow("https://blocked-domain.com/path"));
}

TEST(NetworkPolicy, RemoveRule) {
    NetworkPolicy policy;
    PolicyRule rule;
    rule.pattern = "test-pattern.com";
    rule.allow = false;
    rule.category = "test";
    policy.add_rule(rule);

    EXPECT_FALSE(policy.should_allow("https://test-pattern.com"));

    policy.remove_rule("test-pattern.com");
    EXPECT_TRUE(policy.should_allow("https://test-pattern.com"));
}
