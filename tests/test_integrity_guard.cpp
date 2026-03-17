#include <gtest/gtest.h>
#include "security/integrity_guard.h"

#include <cstring>
#include <vector>

using namespace shieldtier;

TEST(IntegrityGuard, SealAndVerify) {
    IntegrityGuard guard;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    guard.register_region(data.data(), data.size());
    guard.seal();

    EXPECT_TRUE(guard.verify_all());
}

TEST(IntegrityGuard, DetectTampering) {
    IntegrityGuard guard;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    guard.register_region(data.data(), data.size());
    guard.seal();

    // Tamper with data
    data[2] = 0xFF;

    EXPECT_FALSE(guard.verify_all());
}

TEST(IntegrityGuard, MultipleRegions) {
    IntegrityGuard guard;
    std::vector<uint8_t> region1 = {0x10, 0x20, 0x30};
    std::vector<uint8_t> region2 = {0xAA, 0xBB, 0xCC, 0xDD};

    guard.register_region(region1.data(), region1.size());
    guard.register_region(region2.data(), region2.size());
    guard.seal();

    EXPECT_TRUE(guard.verify_all());

    // Tamper with second region
    region2[0] = 0x00;
    EXPECT_FALSE(guard.verify_all());
}

TEST(IntegrityGuard, UnsealedAlwaysPasses) {
    IntegrityGuard guard;
    // Without sealing, verify should return true
    EXPECT_TRUE(guard.verify_all());
}

TEST(IntegrityGuard, CorruptionCallback) {
    IntegrityGuard guard;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    bool callback_called = false;

    guard.register_region(data.data(), data.size());
    guard.set_corruption_callback([&]() { callback_called = true; });
    guard.seal();

    // Tamper
    data[0] = 0xFF;
    guard.check_and_respond();

    EXPECT_TRUE(callback_called);
}

TEST(IntegrityGuard, NoCallbackOnClean) {
    IntegrityGuard guard;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    bool callback_called = false;

    guard.register_region(data.data(), data.size());
    guard.set_corruption_callback([&]() { callback_called = true; });
    guard.seal();

    // No tampering
    guard.check_and_respond();

    EXPECT_FALSE(callback_called);
}
