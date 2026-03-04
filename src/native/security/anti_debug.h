#pragma once

#include <atomic>
#include <thread>

namespace shieldtier {

class AntiDebug {
public:
    void start_monitoring();
    void stop_monitoring();
    bool is_debugger_detected() const;

private:
    bool check_ptrace();
    bool check_proc_status();
    bool check_timing_attack();
    bool check_debug_registers();
    bool check_breakpoint_scan();
    bool check_parent_process();
    bool check_env_vars();
    bool check_exception_handler();
    bool check_hardware_breakpoints();
    bool check_signal_handler();
    bool check_sysctl_debug();
    bool check_dyld_insert();

    std::atomic<bool> debugger_detected_{false};
    std::atomic<bool> monitoring_{false};
    std::jthread monitor_thread_;
};

}  // namespace shieldtier
