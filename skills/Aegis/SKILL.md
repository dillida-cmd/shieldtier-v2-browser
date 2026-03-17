---
name: Aegis
description: Use when building anti-tamper and licensing — anti-debug (12 methods), code self-hashing, integrity guard mesh, silent corruption, machine fingerprint (5-factor), platform keychain (Secure Enclave/DPAPI/Secret Service), encrypted code pages, and rule crypto
---

# S11 — Aegis: Security & Protection

## Overview

Implements all 5 protection layers from PLAN.md: code attestation, hardware-bound licensing, anti-debug mesh, encrypted code pages, and rule crypto. Silent corruption (never crash) is the response to all tamper detection.

## Dependencies

- **Requires:** S10 (scoring engine — protects scoring functions), S0 (libsodium)
- **Blocks:** S12 (cloud validates licenses), S13 (VMProtect wraps these functions)

## File Ownership

```
src/native/security/
  license.cpp/.h          (license validation + tier gating — VMProtect marker)
  fingerprint.cpp/.h      (5-factor machine fingerprint, cross-platform)
  attestation.cpp/.h      (code self-hashing, build-time hash embedding)
  integrity_mesh.cpp/.h   (guard A/B/C cross-validation)
  anti_debug.cpp/.h       (12 detection methods, per-platform)
  encrypted_pages.cpp/.h  (lazy decryption via SIGSEGV/VEH, limited on macOS)
  rule_crypto.cpp/.h      (AES-256-GCM + Ed25519 for rule packages)
  keychain.cpp/.h         (Secure Enclave/DPAPI/Secret Service)
```

## Exit Criteria

License validates against machine fingerprint. Integrity mesh detects binary patching. Anti-debug silently corrupts on debugger attachment. Encrypted rules decrypt only with valid license + matching hardware. Platform keychain stores keys securely.

---

## Machine Fingerprint (5-Factor, Cross-Platform)

```cpp
struct MachineFingerprint {
    std::string cpu_id;
    std::string board_serial;
    std::string disk_serial;
    std::string mac_address;
    std::string os_install_id;
};

MachineFingerprint collect_fingerprint() {
    MachineFingerprint fp;

#if defined(__APPLE__)
    fp.cpu_id = exec_command("sysctl -n machdep.cpu.brand_string");
    fp.board_serial = exec_ioreg("IOPlatformSerialNumber");
    fp.disk_serial = exec_command("diskutil info disk0 | grep 'UUID'");
    fp.mac_address = get_primary_mac();
    fp.os_install_id = exec_ioreg("IOPlatformUUID");

#elif defined(__linux__)
    fp.cpu_id = read_file_first_line("/proc/cpuinfo", "model name");
    fp.board_serial = read_file_trim("/sys/class/dmi/id/board_serial");
    fp.disk_serial = exec_command("lsblk -nd -o SERIAL /dev/sda 2>/dev/null");
    fp.mac_address = get_primary_mac();
    fp.os_install_id = read_file_trim("/etc/machine-id");

#elif defined(_WIN32)
    fp.cpu_id = wmi_query("SELECT ProcessorId FROM Win32_Processor");
    fp.board_serial = wmi_query("SELECT SerialNumber FROM Win32_BaseBoard");
    fp.disk_serial = wmi_query("SELECT SerialNumber FROM Win32_DiskDrive");
    fp.mac_address = get_primary_mac();
    fp.os_install_id = wmi_query("SELECT UUID FROM Win32_ComputerSystemProduct");
#endif

    return fp;
}

// Fuzzy matching: 3 of 5 components must match
bool fingerprint_matches(const MachineFingerprint& stored,
                          const MachineFingerprint& current) {
    int matches = 0;
    if (stored.cpu_id == current.cpu_id) matches++;
    if (stored.board_serial == current.board_serial) matches++;
    if (stored.disk_serial == current.disk_serial) matches++;
    if (stored.mac_address == current.mac_address) matches++;
    if (stored.os_install_id == current.os_install_id) matches++;
    return matches >= 3;  // handles hardware upgrades gracefully
}

// Hash fingerprint for storage
std::string hash_fingerprint(const MachineFingerprint& fp) {
    std::string combined = fp.cpu_id + "|" + fp.board_serial + "|" +
                           fp.disk_serial + "|" + fp.mac_address + "|" +
                           fp.os_install_id;
    uint8_t hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof(hash),
        reinterpret_cast<const uint8_t*>(combined.data()), combined.size(),
        nullptr, 0);
    return bytes_to_hex(hash, sizeof(hash));
}
```

## Anti-Debug Mesh (12 Methods)

```cpp
// All methods return true if debugger detected
// Silent corruption — NEVER crash

namespace anti_debug {

// --- Cross-Platform ---

// 1. Timing check: measure instruction execution time
bool timing_check() {
    auto start = std::chrono::high_resolution_clock::now();
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    auto end = std::chrono::high_resolution_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    return ns > 10000000;  // >10ms for trivial loop = being traced
}

// 2. Hardware breakpoint detection (DR0-DR3)
bool hardware_breakpoints() {
#if defined(__x86_64__) || defined(_M_X64)
    // Use exception handler to read debug registers
    // DR0-DR3 non-zero = hardware breakpoints set
    return false;  // platform-specific implementation below
#endif
    return false;
}

// 3. INT3 scan: CRC of code section detects software breakpoints
bool int3_scan(const uint8_t* code_start, size_t code_size,
               uint32_t expected_crc) {
    uint32_t actual_crc = crc32(code_start, code_size);
    return actual_crc != expected_crc;
}

// 4. Parent process check
bool parent_is_debugger() {
#if defined(__APPLE__) || defined(__linux__)
    pid_t ppid = getppid();
    std::string parent_name = get_process_name(ppid);
    static const std::set<std::string> debuggers = {
        "lldb", "gdb", "strace", "ltrace", "ida", "ida64",
        "radare2", "r2", "x64dbg", "ollydbg"
    };
    return debuggers.count(parent_name) > 0;
#elif defined(_WIN32)
    // Check parent process name
    return false;
#endif
}

// --- macOS Specific ---

#if defined(__APPLE__)
// 5. sysctl P_TRACED flag
bool sysctl_traced() {
    struct kinfo_proc info{};
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, nullptr, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

// 6. ptrace TRACEME (self-trace prevents debugger attachment)
bool ptrace_self() {
    return ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1;
}

// 7. mach_absolute_time timing (more precise than chrono on macOS)
bool mach_timing() {
    uint64_t start = mach_absolute_time();
    // Simple operation that should be fast
    volatile uint32_t x = 0;
    for (int i = 0; i < 100; i++) x ^= i;
    uint64_t end = mach_absolute_time();
    uint64_t diff = end - start;
    return diff > 1000000;  // >1ms for trivial operation = being traced
}
#endif

// --- Linux Specific ---

#if defined(__linux__)
// 8. /proc/self/status TracerPid
bool tracer_pid() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("TracerPid:") == 0) {
            int pid = std::stoi(line.substr(10));
            return pid != 0;
        }
    }
    return false;
}

// 9. Fork watchdog (child traces parent)
bool fork_watchdog() {
    pid_t child = fork();
    if (child == 0) {
        // Child: try to trace parent
        if (ptrace(PTRACE_ATTACH, getppid(), 0, 0) != 0) {
            _exit(1);  // parent already traced
        }
        ptrace(PTRACE_DETACH, getppid(), 0, 0);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    return WEXITSTATUS(status) != 0;
}
#endif

// --- Windows Specific ---

#if defined(_WIN32)
// 10. IsDebuggerPresent
bool is_debugger_present() { return ::IsDebuggerPresent(); }

// 11. PEB.NtGlobalFlag heap debug flags
bool ntglobalflag() {
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    return (peb->NtGlobalFlag & 0x70) != 0;  // FLG_HEAP_*
}

// 12. NtQueryInformationProcess(ProcessDebugPort)
bool debug_port() {
    DWORD_PTR port = 0;
    NtQueryInformationProcess(GetCurrentProcess(), 7, &port, sizeof(port), nullptr);
    return port != 0;
}
#endif

} // namespace anti_debug
```

## Silent Corruption Response

```cpp
// Global corruption state — set by any detection method
static std::atomic<bool> g_corrupted{false};
static uint64_t g_corruption_key = 0;

void trigger_corruption() {
    g_corrupted.store(true, std::memory_order_relaxed);
    // XOR the rule decryption key — encrypted rules won't decrypt properly
    g_corruption_key ^= 0xFFFFFFFFFFFFFFFF;
    // Subtle: delayed corruption kicks in after random 5-30 minute delay
    // Attacker gets "correct" results initially, then garbage later
}

// Called periodically from multiple threads
void anti_debug_check() {
    bool detected = false;

#if defined(__APPLE__)
    detected |= anti_debug::sysctl_traced();
    detected |= anti_debug::mach_timing();
    detected |= anti_debug::parent_is_debugger();
#elif defined(__linux__)
    detected |= anti_debug::tracer_pid();
    detected |= anti_debug::parent_is_debugger();
#elif defined(_WIN32)
    detected |= anti_debug::is_debugger_present();
    detected |= anti_debug::ntglobalflag();
    detected |= anti_debug::debug_port();
#endif

    detected |= anti_debug::timing_check();

    if (detected) trigger_corruption();
}
```

## Integrity Guard Mesh

```cpp
// Guard A hashes Guard B's code. Guard B hashes Guard C's code. Guard C hashes Guard A's code.
// Patching any single guard breaks the chain.

struct GuardRegion {
    const uint8_t* start;
    size_t size;
    uint8_t expected_hash[32];  // SHA-256, embedded at build time
};

void guard_mesh_check() {
    // Guard A checks Guard B
    uint8_t hash_b[32];
    crypto_generichash(hash_b, 32, guard_b.start, guard_b.size, nullptr, 0);
    if (memcmp(hash_b, guard_b.expected_hash, 32) != 0) {
        trigger_corruption();
    }

    // Guard B checks Guard C
    uint8_t hash_c[32];
    crypto_generichash(hash_c, 32, guard_c.start, guard_c.size, nullptr, 0);
    if (memcmp(hash_c, guard_c.expected_hash, 32) != 0) {
        trigger_corruption();
    }

    // Guard C checks Guard A
    uint8_t hash_a[32];
    crypto_generichash(hash_a, 32, guard_a.start, guard_a.size, nullptr, 0);
    if (memcmp(hash_a, guard_a.expected_hash, 32) != 0) {
        trigger_corruption();
    }
}
```

## Platform Keychain

```cpp
class Keychain {
public:
    virtual ~Keychain() = default;
    virtual bool store(const std::string& key, const std::vector<uint8_t>& data) = 0;
    virtual std::vector<uint8_t> retrieve(const std::string& key) = 0;
    virtual bool remove(const std::string& key) = 0;
};

#if defined(__APPLE__)
class MacKeychain : public Keychain {
    bool store(const std::string& key, const std::vector<uint8_t>& data) override {
        CFMutableDictionaryRef query = CFDictionaryCreateMutable(nullptr, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionaryAddValue(query, kSecAttrService,
            CFStringCreateWithCString(nullptr, "com.shieldtier.browser", kCFStringEncodingUTF8));
        CFDictionaryAddValue(query, kSecAttrAccount,
            CFStringCreateWithCString(nullptr, key.c_str(), kCFStringEncodingUTF8));
        CFDictionaryAddValue(query, kSecValueData,
            CFDataCreate(nullptr, data.data(), data.size()));
        CFDictionaryAddValue(query, kSecAttrAccessible,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly);

        OSStatus status = SecItemAdd(query, nullptr);
        CFRelease(query);
        return status == errSecSuccess || status == errSecDuplicateItem;
    }

    std::vector<uint8_t> retrieve(const std::string& key) override {
        CFMutableDictionaryRef query = CFDictionaryCreateMutable(nullptr, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionaryAddValue(query, kSecAttrService,
            CFStringCreateWithCString(nullptr, "com.shieldtier.browser", kCFStringEncodingUTF8));
        CFDictionaryAddValue(query, kSecAttrAccount,
            CFStringCreateWithCString(nullptr, key.c_str(), kCFStringEncodingUTF8));
        CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue);

        CFDataRef result = nullptr;
        OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)&result);
        CFRelease(query);

        if (status != errSecSuccess || !result) return {};

        std::vector<uint8_t> data(CFDataGetBytePtr(result),
            CFDataGetBytePtr(result) + CFDataGetLength(result));
        CFRelease(result);
        return data;
    }

    bool remove(const std::string& key) override { /* SecItemDelete */ return true; }
};
#endif

#if defined(_WIN32)
class DpapiKeychain : public Keychain {
    bool store(const std::string& key, const std::vector<uint8_t>& data) override {
        DATA_BLOB input = {static_cast<DWORD>(data.size()),
                           const_cast<BYTE*>(data.data())};
        DATA_BLOB output;
        if (!CryptProtectData(&input, nullptr, nullptr, nullptr, nullptr,
                               CRYPTPROTECT_LOCAL_MACHINE, &output)) return false;
        // Write encrypted blob to file
        write_file(key_path(key), output.pbData, output.cbData);
        LocalFree(output.pbData);
        return true;
    }

    std::vector<uint8_t> retrieve(const std::string& key) override {
        auto encrypted = read_file(key_path(key));
        DATA_BLOB input = {static_cast<DWORD>(encrypted.size()), encrypted.data()};
        DATA_BLOB output;
        if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output))
            return {};
        std::vector<uint8_t> result(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
        return result;
    }

    bool remove(const std::string& key) override { /* delete file */ return true; }
};
#endif

#if defined(__linux__)
class SecretServiceKeychain : public Keychain {
    // Uses libsecret D-Bus API for GNOME Keyring / KDE Wallet
    bool store(const std::string& key, const std::vector<uint8_t>& data) override {
        SecretSchema schema = {
            "com.shieldtier.browser", SECRET_SCHEMA_NONE,
            {{"key", SECRET_SCHEMA_ATTRIBUTE_STRING}, {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}}
        };
        std::string encoded = base64_encode(data);
        return secret_password_store_sync(&schema, SECRET_COLLECTION_DEFAULT,
            "ShieldTier", encoded.c_str(), nullptr, nullptr, "key", key.c_str(), nullptr);
    }

    std::vector<uint8_t> retrieve(const std::string& key) override {
        SecretSchema schema = { /* same as above */ };
        char* password = secret_password_lookup_sync(&schema, nullptr, nullptr,
            "key", key.c_str(), nullptr);
        if (!password) return {};
        auto result = base64_decode(password);
        secret_password_free(password);
        return result;
    }

    bool remove(const std::string& key) override { /* secret_password_clear_sync */ return true; }
};
#endif

std::unique_ptr<Keychain> create_keychain() {
#if defined(__APPLE__)
    return std::make_unique<MacKeychain>();
#elif defined(_WIN32)
    return std::make_unique<DpapiKeychain>();
#elif defined(__linux__)
    return std::make_unique<SecretServiceKeychain>();
#endif
}
```

## Rule Crypto (AES-256-GCM + Ed25519)

```cpp
// Verify Ed25519 signature on rule package
bool verify_rule_signature(const uint8_t* package, size_t size,
                            const uint8_t server_pubkey[crypto_sign_PUBLICKEYBYTES]) {
    if (size < crypto_sign_BYTES) return false;
    const uint8_t* signature = package;
    const uint8_t* message = package + crypto_sign_BYTES;
    size_t message_len = size - crypto_sign_BYTES;

    return crypto_sign_verify_detached(signature, message, message_len,
                                        server_pubkey) == 0;
}

// Derive rule decryption key from license + hardware
void derive_rule_key(uint8_t out_key[32],
                      const uint8_t* license_key, size_t license_len,
                      const std::string& fingerprint_hash) {
    // HKDF via libsodium's generic hash (BLAKE2b)
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, 32);
    crypto_generichash_update(&state, license_key, license_len);
    crypto_generichash_update(&state,
        reinterpret_cast<const uint8_t*>(fingerprint_hash.data()),
        fingerprint_hash.size());
    const char* info = "shieldtier-rule-key-v2";
    crypto_generichash_update(&state,
        reinterpret_cast<const uint8_t*>(info), strlen(info));
    crypto_generichash_final(&state, out_key, 32);
}
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Crashing on tamper detection | NEVER crash — silent corruption, delayed failure |
| Single anti-debug check | Must use ALL 12 methods — defeating one doesn't help if others active |
| Storing keys in plaintext files | Always use platform keychain (Secure Enclave/DPAPI/Secret Service) |
| Running anti-debug on main thread only | Spawn dedicated watchdog thread, check periodically |
| macOS: encrypted pages via SIGSEGV | Hardened Runtime blocks this — use userspace encrypt/decrypt on macOS |
| Not zeroing derived keys | sodium_memzero on all key material after use |
| Guard mesh hashing wrong region | Use linker section attributes to precisely mark guard boundaries |
| Fingerprint too strict (5-of-5) | Use 3-of-5 — allows single hardware component upgrade |
