#pragma once

#include <string>

namespace shieldtier {

class HardwareFingerprint {
public:
    static std::string generate();

private:
    static std::string get_cpu_id();
    static std::string get_mac_address();
    static std::string get_disk_serial();
    static std::string get_os_uuid();
    static std::string get_secure_element_id();
};

}  // namespace shieldtier
