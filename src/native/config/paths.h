#pragma once

#include <filesystem>
#include <string>

#if defined(_WIN32)
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")
#elif defined(__APPLE__)
#include <pwd.h>
#include <unistd.h>
#else
#include <pwd.h>
#include <unistd.h>
#endif

namespace shieldtier::paths {

namespace {

inline std::string get_home_dir() {
#if defined(_WIN32)
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, path))) {
        return std::string(path);
    }
    const char* home = std::getenv("USERPROFILE");
    return home ? std::string(home) : "C:\\Users\\Default";
#else
    const char* home = std::getenv("HOME");
    if (home && home[0] != '\0') return std::string(home);
    struct passwd* pw = getpwuid(getuid());
    return pw ? std::string(pw->pw_dir) : "/tmp";
#endif
}

inline std::string ensure_dir(const std::string& path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    return path;
}

}  // namespace

/// Config file path: ~/Library/Application Support/ShieldTier/shieldtier.json
inline std::string get_config_path() {
#if defined(_WIN32)
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        auto dir = std::string(path) + "\\ShieldTier";
        ensure_dir(dir);
        return dir + "\\shieldtier.json";
    }
    auto dir = get_home_dir() + "\\AppData\\Roaming\\ShieldTier";
    ensure_dir(dir);
    return dir + "\\shieldtier.json";
#elif defined(__APPLE__)
    auto dir = get_home_dir() + "/Library/Application Support/ShieldTier";
    ensure_dir(dir);
    return dir + "/shieldtier.json";
#else
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    std::string base = xdg ? std::string(xdg) : get_home_dir() + "/.config";
    auto dir = base + "/ShieldTier";
    ensure_dir(dir);
    return dir + "/shieldtier.json";
#endif
}

/// Data directory: ~/Library/Application Support/ShieldTier/
inline std::string get_data_path() {
#if defined(_WIN32)
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        auto dir = std::string(path) + "\\ShieldTier";
        ensure_dir(dir);
        return dir;
    }
    auto dir = get_home_dir() + "\\AppData\\Roaming\\ShieldTier";
    ensure_dir(dir);
    return dir;
#elif defined(__APPLE__)
    auto dir = get_home_dir() + "/Library/Application Support/ShieldTier";
    ensure_dir(dir);
    return dir;
#else
    const char* xdg = std::getenv("XDG_DATA_HOME");
    std::string base = xdg ? std::string(xdg) : get_home_dir() + "/.local/share";
    auto dir = base + "/ShieldTier";
    ensure_dir(dir);
    return dir;
#endif
}

/// Cache directory: ~/Library/Caches/ShieldTier/
inline std::string get_cache_path() {
#if defined(_WIN32)
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path))) {
        auto dir = std::string(path) + "\\ShieldTier\\Cache";
        ensure_dir(dir);
        return dir;
    }
    auto dir = get_home_dir() + "\\AppData\\Local\\ShieldTier\\Cache";
    ensure_dir(dir);
    return dir;
#elif defined(__APPLE__)
    auto dir = get_home_dir() + "/Library/Caches/ShieldTier";
    ensure_dir(dir);
    return dir;
#else
    const char* xdg = std::getenv("XDG_CACHE_HOME");
    std::string base = xdg ? std::string(xdg) : get_home_dir() + "/.cache";
    auto dir = base + "/ShieldTier";
    ensure_dir(dir);
    return dir;
#endif
}

}  // namespace shieldtier::paths
