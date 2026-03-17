#include "security/hardware_fingerprint.h"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#else
#include <openssl/evp.h>
#endif

#if defined(__linux__)
#include <fstream>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#elif defined(_WIN32)
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#endif

namespace shieldtier {

namespace {

std::string sha256_hex(const std::string& input) {
#if defined(__APPLE__)
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(input.data(), static_cast<CC_LONG>(input.size()), digest);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(digest[i]);
    }
    return ss.str();
#else
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, input.data(), input.size());
        EVP_DigestFinal_ex(ctx, digest, &digest_len);
        EVP_MD_CTX_free(ctx);
    }

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_len; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(digest[i]);
    }
    return ss.str();
#endif
}

#if defined(__APPLE__)
std::string cf_string_to_std(CFStringRef cf_str) {
    if (!cf_str) return "";
    CFIndex len = CFStringGetLength(cf_str);
    CFIndex max_size = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string result(static_cast<size_t>(max_size), '\0');
    if (CFStringGetCString(cf_str, result.data(), max_size, kCFStringEncodingUTF8)) {
        result.resize(std::strlen(result.c_str()));
        return result;
    }
    return "";
}
#endif

}  // namespace

// --------------------------------------------------------------------------
// Factor 1: CPU identification
// --------------------------------------------------------------------------
std::string HardwareFingerprint::get_cpu_id() {
#if defined(__APPLE__)
    char brand[256]{};
    size_t len = sizeof(brand);
    if (sysctlbyname("machdep.cpu.brand_string", brand, &len, nullptr, 0) == 0) {
        return std::string(brand);
    }

    // Fallback: get CPU family and model
    int32_t family = 0, model = 0;
    size_t sz = sizeof(int32_t);
    sysctlbyname("hw.cpufamily", &family, &sz, nullptr, 0);
    sysctlbyname("hw.cpusubtype", &model, &sz, nullptr, 0);
    return "cpu:" + std::to_string(family) + ":" + std::to_string(model);
#elif defined(__linux__)
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (!cpuinfo.is_open()) return "unknown-cpu";
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.rfind("model name", 0) == 0) {
            auto pos = line.find(':');
            if (pos != std::string::npos) return line.substr(pos + 2);
        }
    }
    return "unknown-cpu";
#elif defined(_WIN32)
    int cpuinfo_buf[4]{};
    __cpuid(cpuinfo_buf, 0x80000002);
    char brand[49]{};
    std::memcpy(brand, cpuinfo_buf, 16);
    __cpuid(cpuinfo_buf, 0x80000003);
    std::memcpy(brand + 16, cpuinfo_buf, 16);
    __cpuid(cpuinfo_buf, 0x80000004);
    std::memcpy(brand + 32, cpuinfo_buf, 16);
    return std::string(brand);
#else
    return "unknown-cpu";
#endif
}

// --------------------------------------------------------------------------
// Factor 2: Primary MAC address
// --------------------------------------------------------------------------
std::string HardwareFingerprint::get_mac_address() {
#if defined(__APPLE__)
    struct ifaddrs* iflist = nullptr;
    if (getifaddrs(&iflist) != 0) return "unknown-mac";

    std::string result;
    for (auto* ifa = iflist; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;

        auto* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
        if (sdl->sdl_alen != 6) continue;

        auto* mac = reinterpret_cast<const uint8_t*>(LLADDR(sdl));
        // Skip all-zero MACs
        bool all_zero = true;
        for (int i = 0; i < 6; ++i) {
            if (mac[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) continue;

        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 6; ++i) {
            if (i > 0) ss << ':';
            ss << std::setw(2) << static_cast<unsigned>(mac[i]);
        }
        result = ss.str();
        break;  // take first non-loopback interface
    }
    freeifaddrs(iflist);
    return result.empty() ? "unknown-mac" : result;
#elif defined(__linux__)
    struct ifaddrs* iflist = nullptr;
    if (getifaddrs(&iflist) != 0) return "unknown-mac";

    std::string result;
    for (auto* ifa = iflist; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;

        auto* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (sll->sll_halen != 6) continue;

        bool all_zero = true;
        for (int i = 0; i < 6; ++i) {
            if (sll->sll_addr[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) continue;

        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 6; ++i) {
            if (i > 0) ss << ':';
            ss << std::setw(2) << static_cast<unsigned>(sll->sll_addr[i]);
        }
        result = ss.str();
        break;
    }
    freeifaddrs(iflist);
    return result.empty() ? "unknown-mac" : result;
#elif defined(_WIN32)
    IP_ADAPTER_INFO adapters[16]{};
    ULONG buf_len = sizeof(adapters);
    if (GetAdaptersInfo(adapters, &buf_len) != ERROR_SUCCESS) return "unknown-mac";

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < static_cast<int>(adapters[0].AddressLength); ++i) {
        if (i > 0) ss << ':';
        ss << std::setw(2) << static_cast<unsigned>(adapters[0].Address[i]);
    }
    return ss.str();
#else
    return "unknown-mac";
#endif
}

// --------------------------------------------------------------------------
// Factor 3: Boot disk serial number
// --------------------------------------------------------------------------
std::string HardwareFingerprint::get_disk_serial() {
#if defined(__APPLE__)
    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("IOPlatformExpertDevice"));
    if (service == IO_OBJECT_NULL) return "unknown-disk";

    CFTypeRef serial_ref = IORegistryEntryCreateCFProperty(
        service, CFSTR("IOPlatformSerialNumber"),
        kCFAllocatorDefault, 0);
    IOObjectRelease(service);

    if (!serial_ref) return "unknown-disk";
    std::string serial = cf_string_to_std(static_cast<CFStringRef>(serial_ref));
    CFRelease(serial_ref);
    return serial.empty() ? "unknown-disk" : serial;
#elif defined(__linux__)
    // Try reading from sysfs
    std::ifstream serial_file("/sys/class/dmi/id/product_serial");
    if (serial_file.is_open()) {
        std::string serial;
        std::getline(serial_file, serial);
        if (!serial.empty()) return serial;
    }
    return "unknown-disk";
#else
    return "unknown-disk";
#endif
}

// --------------------------------------------------------------------------
// Factor 4: OS / platform UUID
// --------------------------------------------------------------------------
std::string HardwareFingerprint::get_os_uuid() {
#if defined(__APPLE__)
    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("IOPlatformExpertDevice"));
    if (service == IO_OBJECT_NULL) return "unknown-uuid";

    CFTypeRef uuid_ref = IORegistryEntryCreateCFProperty(
        service, CFSTR(kIOPlatformUUIDKey),
        kCFAllocatorDefault, 0);
    IOObjectRelease(service);

    if (!uuid_ref) return "unknown-uuid";
    std::string uuid = cf_string_to_std(static_cast<CFStringRef>(uuid_ref));
    CFRelease(uuid_ref);
    return uuid.empty() ? "unknown-uuid" : uuid;
#elif defined(__linux__)
    std::ifstream uuid_file("/sys/class/dmi/id/product_uuid");
    if (uuid_file.is_open()) {
        std::string uuid;
        std::getline(uuid_file, uuid);
        if (!uuid.empty()) return uuid;
    }
    // Fallback: machine-id
    std::ifstream mid("/etc/machine-id");
    if (mid.is_open()) {
        std::string id;
        std::getline(mid, id);
        if (!id.empty()) return id;
    }
    return "unknown-uuid";
#elif defined(_WIN32)
    // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    HKEY hkey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        char buf[256]{};
        DWORD sz = sizeof(buf);
        if (RegQueryValueExA(hkey, "MachineGuid", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
            RegCloseKey(hkey);
            return std::string(buf);
        }
        RegCloseKey(hkey);
    }
    return "unknown-uuid";
#else
    return "unknown-uuid";
#endif
}

// --------------------------------------------------------------------------
// Factor 5: Secure Element / TPM identifier
// --------------------------------------------------------------------------
std::string HardwareFingerprint::get_secure_element_id() {
#if defined(__APPLE__)
    // On Apple Silicon, the Secure Enclave doesn't expose a direct ID.
    // Use the hardware model identifier as a proxy, combined with
    // IOPlatformSerialNumber (already captured in disk_serial).
    char model[256]{};
    size_t len = sizeof(model);
    if (sysctlbyname("hw.model", model, &len, nullptr, 0) == 0) {
        return std::string(model);
    }
    return "unknown-se";
#elif defined(__linux__)
    // Try reading TPM manufacturer info
    std::ifstream tpm("/sys/class/tpm/tpm0/device/description");
    if (tpm.is_open()) {
        std::string desc;
        std::getline(tpm, desc);
        if (!desc.empty()) return desc;
    }
    return "unknown-se";
#else
    return "unknown-se";
#endif
}

// --------------------------------------------------------------------------
// Combined fingerprint: SHA-256 of all 5 factors
// --------------------------------------------------------------------------
std::string HardwareFingerprint::generate() {
    std::string combined;
    combined += "cpu:" + get_cpu_id() + "|";
    combined += "mac:" + get_mac_address() + "|";
    combined += "disk:" + get_disk_serial() + "|";
    combined += "uuid:" + get_os_uuid() + "|";
    combined += "se:" + get_secure_element_id();

    return sha256_hex(combined);
}

}  // namespace shieldtier
