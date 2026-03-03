#include "vm/vm_manager.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <thread>

#include "common/types.h"

namespace shieldtier {

namespace {

std::string generate_vm_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 255);

    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(16);
    for (int i = 0; i < 8; ++i) {
        auto byte = static_cast<uint8_t>(dist(gen));
        id.push_back(hex_chars[byte >> 4]);
        id.push_back(hex_chars[byte & 0x0f]);
    }
    return id;
}

}  // namespace

VmManager::VmManager(const std::string& vm_base_dir)
    : vm_base_dir_(vm_base_dir) {
    std::filesystem::create_directories(vm_base_dir_);
}

Result<std::string> VmManager::create_vm(const VmConfig& config) {
    if (!std::filesystem::exists(config.image_path)) {
        return Error{"VM image not found: " + config.image_path, "IMAGE_NOT_FOUND"};
    }

    auto vm_id = generate_vm_id();
    auto vm_dir = vm_base_dir_ + "/" + vm_id;

    std::filesystem::create_directories(vm_dir);
    std::filesystem::create_directories(vm_dir + "/samples");
    std::filesystem::create_directories(vm_dir + "/events");

    auto snapshot_path = vm_dir + "/snapshot.qcow2";

    // Create QCOW2 overlay backed by the base image
    // Use posix_spawn/CreateProcess instead of system() to avoid command injection
    {
        auto qemu_img = std::string("qemu-img");
#ifdef _WIN32
        std::string cmd_line = "qemu-img create -f qcow2 -b \"" +
                               config.image_path + "\" -F qcow2 \"" +
                               snapshot_path + "\"";
        STARTUPINFOA si = {};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessA(nullptr, cmd_line.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            std::filesystem::remove_all(vm_dir);
            return Error{"failed to create QCOW2 overlay", "SNAPSHOT_FAILED"};
        }
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exit_code = 1;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (exit_code != 0) {
            std::filesystem::remove_all(vm_dir);
            return Error{"failed to create QCOW2 overlay", "SNAPSHOT_FAILED"};
        }
#else
        std::vector<const char*> argv = {
            "qemu-img", "create", "-f", "qcow2",
            "-b", config.image_path.c_str(),
            "-F", "qcow2", snapshot_path.c_str(), nullptr
        };
        pid_t pid;
        int spawn_status = posix_spawnp(&pid, "qemu-img", nullptr, nullptr,
                                        const_cast<char* const*>(argv.data()),
                                        environ);
        if (spawn_status != 0) {
            std::filesystem::remove_all(vm_dir);
            return Error{"failed to create QCOW2 overlay", "SNAPSHOT_FAILED"};
        }
        int wait_status;
        waitpid(pid, &wait_status, 0);
        if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0) {
            std::filesystem::remove_all(vm_dir);
            return Error{"failed to create QCOW2 overlay", "SNAPSHOT_FAILED"};
        }
#endif
    }

    std::lock_guard<std::mutex> lock(mutex_);

    VmInstance vm;
    vm.id = vm_id;
    vm.state = VmState::kStopped;
    vm.config = config;
    vm.snapshot_path = snapshot_path;

    vms_[vm_id] = std::move(vm);
    return vm_id;
}

Result<bool> VmManager::start_vm(const std::string& vm_id) {
    std::unique_lock<std::mutex> lock(mutex_);

    auto it = vms_.find(vm_id);
    if (it == vms_.end()) {
        return Error{"VM not found: " + vm_id, "NOT_FOUND"};
    }

    auto& vm = it->second;
    if (vm.state != VmState::kStopped) {
        return Error{"VM not in stopped state", "INVALID_STATE"};
    }

    vm.state = VmState::kBooting;
    VmInstance vm_copy = vm;
    lock.unlock();

    auto launch_result = launcher_.launch(vm_copy);
    if (!launch_result.ok()) {
        std::lock_guard<std::mutex> relock(mutex_);
        auto it2 = vms_.find(vm_id);
        if (it2 != vms_.end()) it2->second.state = VmState::kError;
        return Error{launch_result.error().message, launch_result.error().code};
    }

    auto ready_result = wait_for_ready(vm_id, 60000);

    std::lock_guard<std::mutex> relock(mutex_);
    auto it2 = vms_.find(vm_id);
    if (it2 == vms_.end()) {
        launcher_.stop(vm_copy.pid);
        return Error{"VM destroyed during launch", "DESTROYED"};
    }

    it2->second.pid = vm_copy.pid;
    it2->second.monitor_port = vm_copy.monitor_port;
    it2->second.serial_port = vm_copy.serial_port;

    if (!ready_result.ok()) {
        it2->second.state = VmState::kError;
        return Error{"VM failed to become ready: " + ready_result.error().message,
                     "BOOT_TIMEOUT"};
    }

    it2->second.state = VmState::kReady;
    return true;
}

Result<bool> VmManager::stop_vm(const std::string& vm_id) {
    std::unique_lock<std::mutex> lock(mutex_);

    auto it = vms_.find(vm_id);
    if (it == vms_.end()) {
        return Error{"VM not found: " + vm_id, "NOT_FOUND"};
    }

    auto& vm = it->second;
    if (vm.state != VmState::kReady && vm.state != VmState::kAnalyzing &&
        vm.state != VmState::kBooting) {
        return Error{"VM not in a stoppable state", "INVALID_STATE"};
    }

    vm.state = VmState::kShuttingDown;
    int pid = vm.pid;
    lock.unlock();

    auto stop_result = launcher_.stop(pid);

    std::lock_guard<std::mutex> relock(mutex_);
    auto stop_it = vms_.find(vm_id);
    if (stop_it == vms_.end()) return true;

    if (!stop_result.ok()) {
        stop_it->second.state = VmState::kError;
        return Error{stop_result.error().message, stop_result.error().code};
    }

    stop_it->second.state = VmState::kStopped;
    stop_it->second.pid = -1;
    stop_it->second.monitor_port = -1;
    stop_it->second.serial_port = -1;
    return true;
}

Result<bool> VmManager::destroy_vm(const std::string& vm_id) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = vms_.find(vm_id);
        if (it == vms_.end()) {
            return Error{"VM not found: " + vm_id, "NOT_FOUND"};
        }

        if (it->second.state != VmState::kStopped &&
            it->second.state != VmState::kError) {
            // Need to stop first — release lock before calling stop_vm
        } else {
            auto vm_dir = vm_base_dir_ + "/" + vm_id;
            std::filesystem::remove_all(vm_dir);
            vms_.erase(it);
            return true;
        }
    }

    // VM needs to be stopped first
    auto stop_result = stop_vm(vm_id);
    if (!stop_result.ok()) {
        return Error{"failed to stop VM before destroy: " + stop_result.error().message,
                     "DESTROY_FAILED"};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto vm_dir = vm_base_dir_ + "/" + vm_id;
    std::filesystem::remove_all(vm_dir);
    vms_.erase(vm_id);
    return true;
}

Result<VmAnalysisResult> VmManager::submit_sample(
    const std::string& vm_id,
    const FileBuffer& file,
    int timeout_seconds) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = vms_.find(vm_id);
        if (it == vms_.end()) {
            return Error{"VM not found: " + vm_id, "NOT_FOUND"};
        }
        if (it->second.state != VmState::kReady) {
            return Error{"VM not ready for analysis", "INVALID_STATE"};
        }
        it->second.state = VmState::kAnalyzing;
    }

    auto start = std::chrono::steady_clock::now();

    auto inject_result = inject_sample(vm_id, file);
    if (!inject_result.ok()) {
        std::lock_guard<std::mutex> lock(mutex_);
        vms_.at(vm_id).state = VmState::kReady;
        return Error{inject_result.error().message, inject_result.error().code};
    }

    // Poll for events until timeout
    int elapsed = 0;
    while (elapsed < timeout_seconds) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ++elapsed;

        // Check if VM is still running
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = vms_.find(vm_id);
            if (it == vms_.end() || !launcher_.is_running(it->second.pid)) {
                break;
            }
        }
    }

    auto events_result = collect_events(vm_id);
    auto end = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();

    VmAnalysisResult result;
    result.vm_id = vm_id;
    result.duration_ms = duration;

    if (events_result.ok()) {
        result.success = true;
        result.events = std::move(events_result.value());
    } else {
        result.success = false;
        result.error = events_result.error().message;
    }

    result.network_activity = json::object();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = vms_.find(vm_id);
        if (it != vms_.end()) {
            it->second.state = VmState::kReady;
        }
    }

    return result;
}

VmState VmManager::get_state(const std::string& vm_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) {
        return VmState::kStopped;
    }
    return it->second.state;
}

std::vector<VmInstance> VmManager::list_vms() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<VmInstance> result;
    result.reserve(vms_.size());
    for (const auto& [id, vm] : vms_) {
        result.push_back(vm);
    }
    return result;
}

Result<bool> VmManager::wait_for_ready(const std::string& vm_id, int timeout_ms) {
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = vms_.find(vm_id);
            if (it == vms_.end()) {
                return Error{"VM disappeared", "NOT_FOUND"};
            }
            if (!launcher_.is_running(it->second.pid)) {
                return Error{"QEMU process exited during boot", "PROCESS_DIED"};
            }
        }

        // TODO: check QMP readiness via TCP connect to monitor_port
        // For now, treat a running process as ready after brief delay
        if (elapsed >= 2000) {
            return true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        elapsed += 500;
    }

    return Error{"timeout waiting for VM to become ready", "TIMEOUT"};
}

Result<bool> VmManager::inject_sample(const std::string& vm_id,
                                      const FileBuffer& file) {
    auto sample_dir = vm_base_dir_ + "/" + vm_id + "/samples";

    if (!std::filesystem::exists(sample_dir)) {
        std::filesystem::create_directories(sample_dir);
    }

    auto safe_name = std::filesystem::path(file.filename).filename().string();
    if (safe_name.empty() || safe_name == "." || safe_name == "..") {
        safe_name = "sample.bin";
    }
    auto sample_path = sample_dir + "/" + safe_name;

    std::ofstream out(sample_path, std::ios::binary);
    if (!out) {
        return Error{"failed to write sample to " + sample_path, "WRITE_FAILED"};
    }

    out.write(reinterpret_cast<const char*>(file.data.data()),
              static_cast<std::streamsize>(file.data.size()));
    out.close();

    if (!out.good()) {
        return Error{"I/O error writing sample", "WRITE_FAILED"};
    }

    return true;
}

Result<std::vector<json>> VmManager::collect_events(const std::string& vm_id) {
    auto events_dir = vm_base_dir_ + "/" + vm_id + "/events";
    std::vector<json> events;

    if (!std::filesystem::exists(events_dir)) {
        return events;
    }

    for (const auto& entry : std::filesystem::directory_iterator(events_dir)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        std::ifstream in(entry.path(), std::ios::binary);
        if (!in) {
            continue;
        }

        std::string content((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());

        try {
            events.push_back(json::parse(content));
        } catch (const json::parse_error&) {
            // skip malformed event files
        }
    }

    return events;
}

}  // namespace shieldtier
