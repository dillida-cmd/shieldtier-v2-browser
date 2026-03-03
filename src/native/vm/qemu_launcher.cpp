#include "vm/qemu_launcher.h"

#include <cstdlib>
#include <filesystem>
#include <random>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
extern char** environ;
#endif

namespace shieldtier {

QemuLauncher::QemuLauncher() = default;

Result<int> QemuLauncher::launch(VmInstance& vm) {
    auto binary = find_qemu_binary(vm.config.platform);

    vm.monitor_port = allocate_port();
    vm.serial_port = allocate_port();

    auto args = build_args(vm);

#ifdef _WIN32
    std::string cmd = binary;
    for (const auto& arg : args) {
        cmd += " " + arg;
    }

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return Error{"failed to start QEMU process", "LAUNCH_FAILED"};
    }

    CloseHandle(pi.hThread);
    vm.pid = static_cast<int>(pi.dwProcessId);
    CloseHandle(pi.hProcess);
#else
    std::vector<const char*> argv;
    argv.push_back(binary.c_str());
    for (const auto& arg : args) {
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    pid_t pid;
    int status = posix_spawn(&pid, binary.c_str(), nullptr, nullptr,
                             const_cast<char* const*>(argv.data()), environ);
    if (status != 0) {
        return Error{"failed to spawn QEMU: " + std::string(strerror(status)),
                     "LAUNCH_FAILED"};
    }

    vm.pid = static_cast<int>(pid);
#endif

    return vm.pid;
}

Result<bool> QemuLauncher::stop(int pid) {
    if (pid <= 0) {
        return Error{"invalid PID", "INVALID_PID"};
    }

#ifdef _WIN32
    HANDLE proc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                              static_cast<DWORD>(pid));
    if (!proc) {
        return true;
    }

    TerminateProcess(proc, 1);
    WaitForSingleObject(proc, 5000);
    CloseHandle(proc);
    return true;
#else
    if (kill(pid, SIGTERM) != 0) {
        if (errno == ESRCH) {
            return true;
        }
        return Error{"failed to send SIGTERM", "STOP_FAILED"};
    }

    // Wait up to 5 seconds for graceful exit
    for (int i = 0; i < 50; ++i) {
        int status;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid || result == -1) {
            return true;
        }
        usleep(100000);
    }

    // Force kill if still alive
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
    return true;
#endif
}

bool QemuLauncher::is_running(int pid) const {
    if (pid <= 0) {
        return false;
    }

#ifdef _WIN32
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                              static_cast<DWORD>(pid));
    if (!proc) {
        return false;
    }

    DWORD exit_code;
    bool alive = GetExitCodeProcess(proc, &exit_code) && exit_code == STILL_ACTIVE;
    CloseHandle(proc);
    return alive;
#else
    return kill(pid, 0) == 0;
#endif
}

std::string QemuLauncher::find_qemu_binary(VmPlatform platform) const {
    std::string binary_name;
    switch (platform) {
        case VmPlatform::kWindows:
        case VmPlatform::kLinux:
            binary_name = "qemu-system-x86_64";
            break;
        case VmPlatform::kMacOS:
            binary_name = "qemu-system-x86_64";
            break;
    }

    std::vector<std::string> search_paths = {
        "/usr/bin/" + binary_name,
        "/usr/local/bin/" + binary_name,
#ifdef __APPLE__
        "/opt/homebrew/bin/" + binary_name,
#endif
    };

    for (const auto& path : search_paths) {
        if (std::filesystem::exists(path)) {
            return path;
        }
    }

    return binary_name;
}

std::vector<std::string> QemuLauncher::build_args(const VmInstance& vm) const {
    std::vector<std::string> args;

    args.push_back("-machine");
    args.push_back("q35");

    args.push_back("-cpu");
    args.push_back("host");

    args.push_back("-m");
    args.push_back(std::to_string(vm.config.memory_mb));

    args.push_back("-smp");
    args.push_back(std::to_string(vm.config.cpu_cores));

    args.push_back("-display");
    args.push_back("none");

    args.push_back("-drive");
    args.push_back("file=" + vm.snapshot_path + ",format=qcow2");

    args.push_back("-qmp");
    args.push_back("tcp:127.0.0.1:" + std::to_string(vm.monitor_port) +
                   ",server,nowait");

    args.push_back("-serial");
    args.push_back("tcp:127.0.0.1:" + std::to_string(vm.serial_port) +
                   ",server,nowait");

    if (vm.config.enable_network) {
        args.push_back("-nic");
        args.push_back("user,model=e1000");
    } else {
        args.push_back("-nic");
        args.push_back("none");
    }

    if (!vm.config.snapshot_name.empty()) {
        args.push_back("-loadvm");
        args.push_back(vm.config.snapshot_name);
    }

    // Hardware acceleration
#ifdef __APPLE__
    args.push_back("-accel");
    args.push_back("hvf");
#elif defined(__linux__)
    args.push_back("-accel");
    args.push_back("kvm");
#endif

    return args;
}

int QemuLauncher::allocate_port() const {
    // Bind to port 0 to let the OS assign a free port, then close
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    int sock = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    if (sock < 0) {
        // Fallback: random port in ephemeral range
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(10000, 60000);
        return dist(gen);
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(10000, 60000);
        return dist(gen);
    }

    socklen_t len = sizeof(addr);
    getsockname(sock, reinterpret_cast<struct sockaddr*>(&addr), &len);
    int port = ntohs(addr.sin_port);

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    return port;
}

}  // namespace shieldtier
