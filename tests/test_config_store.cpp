#include <gtest/gtest.h>
#include "config/config_store.h"

#include <filesystem>
#include <fstream>

using namespace shieldtier;

class ConfigStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_path_ = std::filesystem::temp_directory_path() / "shieldtier_test_config.json";
        std::filesystem::remove(test_path_);
    }

    void TearDown() override {
        std::filesystem::remove(test_path_);
    }

    std::filesystem::path test_path_;
};

TEST_F(ConfigStoreTest, SetAndGet) {
    ConfigStore store(test_path_.string());
    store.set("theme", "dark");
    EXPECT_EQ(store.get("theme"), "dark");
}

TEST_F(ConfigStoreTest, GetWithDefault) {
    ConfigStore store(test_path_.string());
    EXPECT_EQ(store.get("nonexistent", "fallback"), "fallback");
}

TEST_F(ConfigStoreTest, HasKey) {
    ConfigStore store(test_path_.string());
    EXPECT_FALSE(store.has("key"));
    store.set("key", 42);
    EXPECT_TRUE(store.has("key"));
}

TEST_F(ConfigStoreTest, RemoveKey) {
    ConfigStore store(test_path_.string());
    store.set("key", "value");
    EXPECT_TRUE(store.has("key"));
    store.remove("key");
    EXPECT_FALSE(store.has("key"));
}

TEST_F(ConfigStoreTest, SaveAndLoad) {
    {
        ConfigStore store(test_path_.string());
        store.set("api_key", "test-key-123");
        store.set("max_files", 100);
        auto result = store.save();
        EXPECT_TRUE(result.ok());
    }

    // Load in a new instance
    {
        ConfigStore store(test_path_.string());
        auto result = store.load();
        EXPECT_TRUE(result.ok());
        EXPECT_EQ(store.get("api_key"), "test-key-123");
        EXPECT_EQ(store.get("max_files"), 100);
    }
}

TEST_F(ConfigStoreTest, MergeOverrides) {
    ConfigStore store(test_path_.string());
    store.set("a", 1);
    store.set("b", 2);

    nlohmann::json overrides;
    overrides["b"] = 20;
    overrides["c"] = 30;
    store.merge(overrides);

    EXPECT_EQ(store.get("a"), 1);
    EXPECT_EQ(store.get("b"), 20);
    EXPECT_EQ(store.get("c"), 30);
}
