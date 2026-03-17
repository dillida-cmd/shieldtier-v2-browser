#include <gtest/gtest.h>
#include "analysis/loganalysis/log_manager.h"
#include "analysis/loganalysis/log_normalizer.h"

using namespace shieldtier;

TEST(LogNormalizer, Construct) {
    LogNormalizer normalizer;
    SUCCEED();
}

TEST(LogNormalizer, NormalizeEmptyVector) {
    LogNormalizer normalizer;
    std::vector<NormalizedEvent> events;
    normalizer.normalize(events);
    EXPECT_TRUE(events.empty());
}

TEST(LogNormalizer, NormalizeSingleEvent) {
    LogNormalizer normalizer;
    std::vector<NormalizedEvent> events;
    NormalizedEvent evt;
    evt.source = "test";
    evt.message = "Test event";
    evt.severity = Severity::kInfo;
    events.push_back(evt);

    normalizer.normalize(events);
    EXPECT_EQ(events.size(), 1u);
}
