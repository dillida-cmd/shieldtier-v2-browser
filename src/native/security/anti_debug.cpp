#include "security/anti_debug.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string>

#if defined(__APPLE__)
#include <dlfcn.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#elif defined(__linux__)
#include <dlfcn.h>
#include <fstream>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace shieldtier {

namespace {

#if defined(__APPLE__) || defined(__linux__)
volatile sig_atomic_t g_sigtrap_caught = 0;

void sigtrap_handler(int) {
    g_sigtrap_caught = 1;
}
#endif

}  // namespace

void AntiDebug::start_monitoring() {
    if (monitoring_.exchange(true)) return;
    debugger_detected_.store(false);

    monitor_thread_ = std::jthread([this](std::stop_token token) {
        while (!token.stop_requested()) {
            bool detected =
                check_ptrace() ||
                check_proc_status() ||
                check_timing_attack() ||
                check_debug_registers() ||
                check_breakpoint_scan() ||
                check_parent_process() ||
                check_env_vars() ||
                check_exception_handler() ||
                check_hardware_breakpoints() ||
                check_signal_handler() ||
                check_sysctl_debug() ||
                check_dyld_insert();

            if (detected) {
                debugger_detected_.store(true);
            }

            for (int i = 0; i < 50 && !token.stop_requested(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    });
}

void AntiDebug::stop_monitoring() {
    if (!monitoring_.exchange(false)) return;
    if (monitor_thread_.joinable()) {
        monitor_thread_.request_stop();
        monitor_thread_.join();
    }
}

bool AntiDebug::is_debugger_detected() const {
    return debugger_detected_.load();
}

// --------------------------------------------------------------------------
// 1. PT_DENY_ATTACH (macOS) / PTRACE_TRACEME (Linux)
// --------------------------------------------------------------------------
bool AntiDebug::check_ptrace() {
#if defined(__APPLE__)
    // PT_DENY_ATTACH = 31. If a debugger is attached this call fails.
    using ptrace_fn = int (*)(int, pid_t, caddr_t, int);
    auto pt = reinterpret_cast<ptrace_fn>(dlsym(RTLD_DEFAULT, "ptrace"));
    if (!pt) return false;
    int rc = pt(31 /* PT_DENY_ATTACH */, 0, nullptr, 0);
    // If a debugger is attached, ptrace returns -1 and we get killed —
    // but in monitoring mode we only want passive detection, so we check
    // via sysctl instead (see check_sysctl_debug). This call is therefore
    // a one-shot that only works at startup. Return false here to avoid
    // killing the process if no debugger is attached.
    (void)rc;
    return false;
#elif defined(__linux__)
    long rc = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    if (rc == -1) {
        return true;  // already being traced
    }
    // Detach ourselves
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
    return false;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 2. /proc/self/status TracerPid (Linux) / sysctl P_TRACED (macOS)
// --------------------------------------------------------------------------
bool AntiDebug::check_proc_status() {
#if defined(__linux__)
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return false;
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            long pid = std::strtol(line.c_str() + 10, nullptr, 10);
            return pid != 0;
        }
    }
    return false;
#elif defined(__APPLE__)
    struct kinfo_proc info{};
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t sz = sizeof(info);
    if (sysctl(mib, 4, &info, &sz, nullptr, 0) != 0) return false;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 3. Timing attack — tight loop duration check
// --------------------------------------------------------------------------
bool AntiDebug::check_timing_attack() {
    constexpr int iterations = 500000;
    auto start = std::chrono::steady_clock::now();
    volatile int sink = 0;
    for (int i = 0; i < iterations; ++i) {
        sink += i;
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

    // On a modern CPU this loop completes in ~200-500us.
    // If a debugger is stepping, it can take 10x or more.
    // Use a generous 50ms threshold to avoid false positives.
    return us > 50000;
}

// --------------------------------------------------------------------------
// 4. Debug registers (DR0-DR7)
// --------------------------------------------------------------------------
bool AntiDebug::check_debug_registers() {
#if defined(__APPLE__) && defined(__x86_64__)
    x86_debug_state64_t dbg_state{};
    mach_msg_type_number_t count = x86_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(
        mach_thread_self(), x86_DEBUG_STATE64,
        reinterpret_cast<thread_state_t>(&dbg_state), &count);
    if (kr != KERN_SUCCESS) return false;
    return dbg_state.__dr0 != 0 || dbg_state.__dr1 != 0 ||
           dbg_state.__dr2 != 0 || dbg_state.__dr3 != 0;
#elif defined(__linux__) && defined(__x86_64__)
    // Reading debug registers on Linux requires ptrace from a parent; skip.
    return false;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 5. Breakpoint scan — look for INT3 (0xCC) in .text
// --------------------------------------------------------------------------
bool AntiDebug::check_breakpoint_scan() {
#if defined(__APPLE__) || defined(__linux__) || defined(_WIN32)
    // Scan a well-known libc function for INT3 software breakpoints.
    // If a debugger has placed a breakpoint on malloc, we'll detect it.
    auto fn_addr = reinterpret_cast<const uint8_t*>(
        reinterpret_cast<uintptr_t>(&malloc));
    for (size_t i = 0; i < 64; ++i) {
        if (fn_addr[i] == 0xCC) return true;
    }
    return false;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 6. Parent process check — known debugger names
// --------------------------------------------------------------------------
bool AntiDebug::check_parent_process() {
#if defined(__APPLE__)
    pid_t ppid = getppid();
    char name[PROC_PIDPATHINFO_MAXSIZE]{};
    if (proc_pidpath(ppid, name, sizeof(name)) <= 0) return false;

    static constexpr const char* debuggers[] = {
        "lldb", "gdb", "debugserver", "dtrace", "strace", "frida", "ida"};
    std::string path(name);
    for (auto* dbg : debuggers) {
        if (path.find(dbg) != std::string::npos) return true;
    }
    return false;
#elif defined(__linux__)
    pid_t ppid = getppid();
    std::string proc_path = "/proc/" + std::to_string(ppid) + "/comm";
    std::ifstream comm(proc_path);
    if (!comm.is_open()) return false;
    std::string name;
    std::getline(comm, name);

    static constexpr const char* debuggers[] = {
        "lldb", "gdb", "strace", "ltrace", "frida", "ida", "radare2", "r2"};
    for (auto* dbg : debuggers) {
        if (name.find(dbg) != std::string::npos) return true;
    }
    return false;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 7. Environment variable injection detection
// --------------------------------------------------------------------------
bool AntiDebug::check_env_vars() {
#if defined(__APPLE__)
    return std::getenv("DYLD_INSERT_LIBRARIES") != nullptr ||
           std::getenv("DYLD_LIBRARY_PATH") != nullptr;
#elif defined(__linux__)
    return std::getenv("LD_PRELOAD") != nullptr;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 8. Exception-based detection — raise SIGTRAP, see if our handler catches it
// --------------------------------------------------------------------------
bool AntiDebug::check_exception_handler() {
#if defined(__APPLE__) || defined(__linux__)
    g_sigtrap_caught = 0;
    struct sigaction sa{}, old_sa{};
    sa.sa_handler = sigtrap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTRAP, &sa, &old_sa) != 0) return false;
    raise(SIGTRAP);
    sigaction(SIGTRAP, &old_sa, nullptr);

    // If our handler ran, no debugger intercepted SIGTRAP
    return g_sigtrap_caught == 0;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 9. Hardware breakpoints via thread_get_state (macOS)
// --------------------------------------------------------------------------
bool AntiDebug::check_hardware_breakpoints() {
#if defined(__APPLE__) && defined(__x86_64__)
    // Same as check_debug_registers for x86_64 macOS
    return check_debug_registers();
#elif defined(__APPLE__) && defined(__aarch64__)
    // ARM64: check BVR (breakpoint value registers) via thread state
    arm_debug_state64_t dbg{};
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(
        mach_thread_self(), ARM_DEBUG_STATE64,
        reinterpret_cast<thread_state_t>(&dbg), &count);
    if (kr != KERN_SUCCESS) return false;
    for (int i = 0; i < 16; ++i) {
        if (dbg.__bvr[i] != 0) return true;
    }
    return false;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 10. Signal handler verification — install SIGTRAP handler, verify it runs
// --------------------------------------------------------------------------
bool AntiDebug::check_signal_handler() {
#if defined(__APPLE__) || defined(__linux__)
    g_sigtrap_caught = 0;
    struct sigaction sa{}, old_sa{};
    sa.sa_handler = sigtrap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTRAP, &sa, &old_sa) != 0) return false;

    // Verify our handler was installed by reading it back
    struct sigaction current{};
    sigaction(SIGTRAP, nullptr, &current);
    bool handler_matches = (current.sa_handler == sigtrap_handler);

    sigaction(SIGTRAP, &old_sa, nullptr);
    return !handler_matches;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 11. sysctl P_TRACED check (macOS)
// --------------------------------------------------------------------------
bool AntiDebug::check_sysctl_debug() {
#if defined(__APPLE__)
    struct kinfo_proc info{};
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t sz = sizeof(info);
    if (sysctl(mib, 4, &info, &sz, nullptr, 0) != 0) return false;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------
// 12. DYLD_INSERT_LIBRARIES detection (macOS-specific library injection)
// --------------------------------------------------------------------------
bool AntiDebug::check_dyld_insert() {
#if defined(__APPLE__)
    const char* val = std::getenv("DYLD_INSERT_LIBRARIES");
    if (val != nullptr && val[0] != '\0') return true;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char* name = _dyld_get_image_name(i);
        if (name) {
            std::string img(name);
            if (img.find("frida") != std::string::npos ||
                img.find("cycript") != std::string::npos ||
                img.find("substrate") != std::string::npos) {
                return true;
            }
        }
    }
    return false;
#else
    return false;
#endif
}

}  // namespace shieldtier
