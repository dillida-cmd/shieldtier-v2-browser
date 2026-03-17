#pragma once

#include <mutex>
#include <string>

#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

class ConfigStore {
public:
    explicit ConfigStore(const std::string& config_path);

    Result<json> load();
    Result<bool> save();

    json get(const std::string& key, const json& default_val = nullptr) const;
    void set(const std::string& key, const json& value);
    bool has(const std::string& key) const;
    void remove(const std::string& key);
    json get_all() const;
    void merge(const json& overrides);

private:
    Result<bool> write_atomic(const std::string& path, const std::string& data);

    std::string config_path_;
    json config_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
