#pragma once

#include <string>
#include <vector>
#include "common/json.h"

namespace shieldtier {

struct AntiEvasionConfig {
    bool mask_cpuid = true;        // hide hypervisor bit
    bool randomize_mac = true;
    bool randomize_serial = true;
    bool realistic_disk_size = true;
    bool add_fake_processes = true;
    bool set_realistic_uptime = true;
};

class AntiEvasion {
public:
    explicit AntiEvasion(const AntiEvasionConfig& config = {});

    // Generate QEMU args for anti-evasion
    std::vector<std::string> get_qemu_args() const;

    // Generate registry/config patches for the guest OS
    json get_guest_patches(const std::string& platform) const;

private:
    std::string generate_serial() const;
    std::string generate_mac() const;
    std::string generate_bios_vendor() const;

    AntiEvasionConfig config_;
};

}  // namespace shieldtier
