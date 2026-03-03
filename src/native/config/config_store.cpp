#include "config/config_store.h"

#include <cstdio>
#include <fstream>
#include <sstream>

#ifdef _POSIX_VERSION
#include <fcntl.h>
#include <unistd.h>
#endif

namespace shieldtier {

ConfigStore::ConfigStore(const std::string& config_path)
    : config_path_(config_path), config_(json::object()) {}

Result<json> ConfigStore::load() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ifstream file(config_path_);
    if (!file.is_open()) {
        return Error("Failed to open config file: " + config_path_, "file_not_found");
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    try {
        config_ = json::parse(buffer.str());
    } catch (const json::parse_error& e) {
        return Error(std::string("JSON parse error: ") + e.what(), "parse_error");
    }

    return config_;
}

Result<bool> ConfigStore::save() {
    std::lock_guard<std::mutex> lock(mutex_);
    return write_atomic(config_path_, config_.dump(4));
}

json ConfigStore::get(const std::string& key, const json& default_val) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (config_.contains(key)) {
        return config_[key];
    }
    return default_val;
}

void ConfigStore::set(const std::string& key, const json& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_[key] = value;
}

bool ConfigStore::has(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.contains(key);
}

void ConfigStore::remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.erase(key);
}

json ConfigStore::get_all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

void ConfigStore::merge(const json& overrides) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.merge_patch(overrides);
}

Result<bool> ConfigStore::write_atomic(const std::string& path, const std::string& data) {
    std::string tmp_path = path + ".tmp";

    std::ofstream file(tmp_path, std::ios::trunc);
    if (!file.is_open()) {
        return Error("Failed to open temp file for writing: " + tmp_path, "write_error");
    }

    file << data;
    file.flush();

    if (file.fail()) {
        file.close();
        std::remove(tmp_path.c_str());
        return Error("Failed to write config data", "write_error");
    }
    file.close();

#ifdef _POSIX_VERSION
    int fd = ::open(tmp_path.c_str(), O_RDONLY);
    if (fd >= 0) {
        ::fdatasync(fd);
        ::close(fd);
    }
#endif

    if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
        std::remove(tmp_path.c_str());
        return Error("Failed to rename temp file to config path", "rename_error");
    }

    return true;
}

}  // namespace shieldtier
