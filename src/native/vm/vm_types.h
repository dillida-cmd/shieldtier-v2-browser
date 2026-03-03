#pragma once

#include <string>
#include <vector>

#include "common/json.h"

namespace shieldtier {

enum class VmState {
    kCreating, kBooting, kReady, kAnalyzing, kShuttingDown, kStopped, kError
};

NLOHMANN_JSON_SERIALIZE_ENUM(VmState, {
    {VmState::kCreating, "creating"},
    {VmState::kBooting, "booting"},
    {VmState::kReady, "ready"},
    {VmState::kAnalyzing, "analyzing"},
    {VmState::kShuttingDown, "shutting_down"},
    {VmState::kStopped, "stopped"},
    {VmState::kError, "error"},
})

enum class VmPlatform { kWindows, kLinux, kMacOS };

NLOHMANN_JSON_SERIALIZE_ENUM(VmPlatform, {
    {VmPlatform::kWindows, "windows"},
    {VmPlatform::kLinux, "linux"},
    {VmPlatform::kMacOS, "macos"},
})

struct VmConfig {
    VmPlatform platform;
    int cpu_cores = 2;
    int memory_mb = 2048;
    int disk_gb = 20;
    std::string snapshot_name;
    std::string image_path;
    int analysis_timeout_seconds = 300;
    bool enable_network = true;
    bool enable_inetsim = true;
};

struct VmInstance {
    std::string id;
    VmState state;
    VmConfig config;
    int pid = -1;
    int monitor_port = -1;
    int serial_port = -1;
    std::string snapshot_path;
};

struct VmAnalysisResult {
    std::string vm_id;
    bool success;
    std::string error;
    std::vector<json> events;
    double duration_ms;
    json network_activity;
};

}  // namespace shieldtier
