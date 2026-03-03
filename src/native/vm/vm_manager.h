#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

#include "common/result.h"
#include "vm/vm_types.h"
#include "vm/qemu_launcher.h"

namespace shieldtier {

class VmManager {
public:
    explicit VmManager(const std::string& vm_base_dir);

    Result<std::string> create_vm(const VmConfig& config);
    Result<bool> start_vm(const std::string& vm_id);
    Result<bool> stop_vm(const std::string& vm_id);
    Result<bool> destroy_vm(const std::string& vm_id);

    Result<VmAnalysisResult> submit_sample(
        const std::string& vm_id,
        const FileBuffer& file,
        int timeout_seconds = 300);

    VmState get_state(const std::string& vm_id) const;
    std::vector<VmInstance> list_vms() const;

private:
    Result<bool> wait_for_ready(const std::string& vm_id, int timeout_ms);
    Result<bool> inject_sample(const std::string& vm_id, const FileBuffer& file);
    Result<std::vector<json>> collect_events(const std::string& vm_id);

    std::string vm_base_dir_;
    std::unordered_map<std::string, VmInstance> vms_;
    mutable std::mutex mutex_;
    QemuLauncher launcher_;
};

}  // namespace shieldtier
