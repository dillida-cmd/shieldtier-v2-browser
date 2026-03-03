#pragma once

#include <string>
#include <vector>

#include "common/result.h"
#include "vm/vm_types.h"

namespace shieldtier {

class QemuLauncher {
public:
    QemuLauncher();

    Result<int> launch(VmInstance& vm);
    Result<bool> stop(int pid);
    bool is_running(int pid) const;

    std::string find_qemu_binary(VmPlatform platform) const;

private:
    std::vector<std::string> build_args(const VmInstance& vm) const;
    int allocate_port() const;
};

}  // namespace shieldtier
