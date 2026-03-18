#include "analysis/loganalysis/shieldy_bridge.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>

namespace shieldtier {

namespace {

/// Run a command and capture its stdout. Returns empty string on failure.
std::string exec_capture(const std::string& cmd, int& exit_code, int timeout_sec = 120) {
    // Add timeout wrapper on macOS/Linux
    std::string wrapped_cmd;
#ifdef _WIN32
    wrapped_cmd = cmd;
#else
    wrapped_cmd = "timeout " + std::to_string(timeout_sec) + " " + cmd;
#endif
    wrapped_cmd += " 2>/dev/null";

    FILE* pipe = popen(wrapped_cmd.c_str(), "r");
    if (!pipe) {
        exit_code = -1;
        return "";
    }

    std::string output;
    std::array<char, 8192> buffer;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }

    int status = pclose(pipe);
#ifdef _WIN32
    exit_code = status;
#else
    exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
    return output;
}

/// Shell-escape a path for safe subprocess usage.
std::string shell_escape(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out += c;
        }
    }
    out += "'";
    return out;
}

}  // namespace

ShieldyBridge::ShieldyBridge()
    : python_path_(find_python()),
      bridge_path_(find_bridge_script()) {}

bool ShieldyBridge::available() const {
    return !python_path_.empty() && !bridge_path_.empty();
}

std::string ShieldyBridge::find_python() {
    // Prefer user-installed Python (has pip packages) over Xcode's /usr/bin/python3.
    // Order: PATH lookup first (finds user's default), then Homebrew/Framework,
    // then /usr/bin/python3 as last resort (Xcode CLT — often lacks pip packages).

    // 1. PATH lookup — best option, finds whatever `python3` the user has configured
    int exit_code = 0;
    std::string result = exec_capture("which python3", exit_code);
    if (exit_code == 0 && !result.empty()) {
        while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
            result.pop_back();
        }
        if (std::filesystem::exists(result)) {
            return result;
        }
    }

    // 2. Common user-installed Python locations (prefer these over /usr/bin)
    const char* candidates[] = {
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3",
        "/opt/local/bin/python3",
        "/usr/bin/python3",  // Xcode CLT — last resort
    };

    for (const char* path : candidates) {
        if (std::filesystem::exists(path)) {
            return path;
        }
    }

    return "";
}

std::string ShieldyBridge::find_bridge_script() {
    namespace fs = std::filesystem;

    // Check known development paths
    const char* candidates[] = {
        "/Users/dilli/Desktop/shieldy/shieldy_cli_bridge.py",
    };

    for (const char* path : candidates) {
        if (fs::exists(path)) {
            return path;
        }
    }

    // Check relative to executable (for packaged builds)
    try {
        // macOS: look in Resources directory of the .app bundle
        auto exe_path = fs::read_symlink("/proc/self/exe");
        auto resources = exe_path.parent_path().parent_path() / "Resources" / "shieldy" / "shieldy_cli_bridge.py";
        if (fs::exists(resources)) {
            return resources.string();
        }
    } catch (...) {}

    // Also check HOME
    const char* home = std::getenv("HOME");
    if (home) {
        std::string home_path = std::string(home) + "/shieldy/shieldy_cli_bridge.py";
        if (fs::exists(home_path)) {
            return home_path;
        }
    }

    return "";
}

Result<ShieldyBridge::ShieldyResult> ShieldyBridge::analyze(const std::string& file_path) {
    if (!available()) {
        return Error("Shieldy bridge not available (python3 or bridge script not found)");
    }

    if (!std::filesystem::exists(file_path)) {
        return Error("File not found: " + file_path);
    }

    // Build command: python3 /path/to/shieldy_cli_bridge.py '/path/to/logfile'
    std::string cmd = shell_escape(python_path_) + " "
                    + shell_escape(bridge_path_) + " "
                    + shell_escape(file_path);

    int exit_code = 0;
    std::string stdout_data = exec_capture(cmd, exit_code, 300);  // 5 min timeout

    if (exit_code != 0 && stdout_data.empty()) {
        return Error("Shieldy subprocess failed with exit code " + std::to_string(exit_code));
    }

    // Parse JSON output
    json output;
    try {
        output = json::parse(stdout_data);
    } catch (const json::parse_error& e) {
        return Error("Failed to parse Shieldy JSON output: " + std::string(e.what()));
    }

    // Check for error in output
    if (output.contains("error") && output["error"].is_string()) {
        std::string err = output["error"].get<std::string>();
        if (!err.empty() && !output.contains("events")) {
            return Error("Shieldy analysis error: " + err);
        }
    }

    // Map to ShieldyResult
    ShieldyResult result;
    result.format = output.value("format", "unknown");
    result.event_count = output.value("eventCount", 0);
    result.parse_errors = output.value("parseErrors", 0);
    result.severity_counts = output.value("severityCounts", json::object());
    result.category_counts = output.value("categoryCounts", json::object());
    result.events = output.value("events", json::array());
    result.insights = output.value("insights", json::array());
    result.triage = output.value("triage", json(nullptr));
    result.investigation = output.value("investigation", json(nullptr));
    result.graph = output.value("graph", json(nullptr));
    result.verdict = output.value("verdict", json(nullptr));
    result.hunting = output.value("hunting", json(nullptr));

    return result;
}

}  // namespace shieldtier
