#include "vm/vm_installer.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>

#include <curl/curl.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#elif !defined(_WIN32)
extern char** environ;
#endif

namespace shieldtier {

namespace {

std::once_flag g_curl_init;

void ensure_curl() {
    std::call_once(g_curl_init, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

struct DownloadContext {
    std::ofstream* file;
    ProgressCallback* on_progress;
    std::string image_id;
    std::atomic<bool>* cancel;
    int64_t total_bytes;
    int64_t downloaded_bytes;
    int last_percent;
};

size_t download_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* ctx = static_cast<DownloadContext*>(userdata);
    if (ctx->cancel && ctx->cancel->load()) return 0;  // abort

    size_t total = size * nmemb;
    ctx->file->write(ptr, static_cast<std::streamsize>(total));
    if (!ctx->file->good()) return 0;

    ctx->downloaded_bytes += static_cast<int64_t>(total);
    return total;
}

int download_progress_cb(void* clientp, curl_off_t dltotal, curl_off_t dlnow,
                          curl_off_t /*ultotal*/, curl_off_t /*ulnow*/) {
    auto* ctx = static_cast<DownloadContext*>(clientp);
    if (ctx->cancel && ctx->cancel->load()) return 1;  // abort

    if (dltotal <= 0) return 0;

    int percent = static_cast<int>((dlnow * 100) / dltotal);
    if (percent == ctx->last_percent) return 0;  // debounce
    ctx->last_percent = percent;

    double dl_mb = static_cast<double>(dlnow) / (1024.0 * 1024.0);
    double total_mb = static_cast<double>(dltotal) / (1024.0 * 1024.0);

    if (ctx->on_progress) {
        (*ctx->on_progress)({
            {"imageId", ctx->image_id},
            {"status", "downloading"},
            {"progress", percent},
            {"downloadedMB", dl_mb},
            {"totalMB", total_mb}
        });
    }

    return 0;
}

#ifndef _WIN32
int run_command(const std::vector<std::string>& args) {
    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) argv.push_back(arg.c_str());
    argv.push_back(nullptr);

    pid_t pid;
    int status = posix_spawnp(&pid, argv[0], nullptr, nullptr,
                               const_cast<char* const*>(argv.data()), environ);
    if (status != 0) return -1;

    int wait_status;
    waitpid(pid, &wait_status, 0);
    if (WIFEXITED(wait_status)) return WEXITSTATUS(wait_status);
    return -1;
}
#endif

}  // namespace

VmInstaller::VmInstaller(const std::string& data_dir)
    : data_dir_(data_dir),
      images_dir_(data_dir + "/images") {
    std::filesystem::create_directories(images_dir_);
}

Result<std::string> VmInstaller::find_qemu() const {
    // Search for qemu-system-x86_64 in common paths
    std::vector<std::string> candidates;

#ifdef _WIN32
    // Windows: check Program Files, choco, scoop, and PATH
    const char* program_files = std::getenv("ProgramFiles");
    if (program_files) {
        candidates.push_back(std::string(program_files) + "\\qemu\\qemu-system-x86_64.exe");
        candidates.push_back(std::string(program_files) + "\\qemu\\qemu-system-x86_64w.exe");
    }
    // Scoop
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile) {
        candidates.push_back(std::string(userprofile) + "\\scoop\\shims\\qemu-system-x86_64.exe");
    }
    // Chocolatey
    candidates.push_back("C:\\ProgramData\\chocolatey\\bin\\qemu-system-x86_64.exe");
#else
    candidates.push_back("/usr/bin/qemu-system-x86_64");
    candidates.push_back("/usr/local/bin/qemu-system-x86_64");
#ifdef __APPLE__
    candidates.push_back("/opt/homebrew/bin/qemu-system-x86_64");
#endif
#endif

    for (const auto& path : candidates) {
        if (std::filesystem::exists(path)) {
            return path;
        }
    }

    // Try PATH lookup via which/where
#ifdef _WIN32
    // Use _popen to check 'where qemu-system-x86_64'
    FILE* pipe = _popen("where qemu-system-x86_64.exe 2>nul", "r");
    if (pipe) {
        char buf[512];
        std::string result;
        while (fgets(buf, sizeof(buf), pipe)) {
            result += buf;
        }
        _pclose(pipe);
        // Take first line
        auto nl = result.find('\n');
        if (nl != std::string::npos) result = result.substr(0, nl);
        // Trim \r
        while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
            result.pop_back();
        if (!result.empty() && std::filesystem::exists(result)) {
            return result;
        }
    }
#else
    FILE* pipe = popen("which qemu-system-x86_64 2>/dev/null", "r");
    if (pipe) {
        char buf[512];
        std::string result;
        while (fgets(buf, sizeof(buf), pipe)) result += buf;
        pclose(pipe);
        while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
            result.pop_back();
        if (!result.empty() && std::filesystem::exists(result)) {
            return result;
        }
    }
#endif

    return Error{"QEMU not found", "NOT_FOUND"};
}

Result<std::string> VmInstaller::install_qemu(ProgressCallback on_progress) {
    // Check if already installed
    auto existing = find_qemu();
    if (existing.ok()) {
        on_progress({{"status", "complete"}, {"progress", 100},
                     {"log", "QEMU already installed at " + existing.value()}});
        return existing.value();
    }

    on_progress({{"status", "installing"}, {"progress", 10},
                 {"log", "Detecting platform..."}});

#ifdef _WIN32
    // Windows: Download QEMU installer from official site
    on_progress({{"status", "installing"}, {"progress", 15},
                 {"log", "Attempting to install QEMU via winget..."}});

    // Try winget first (Windows 10+)
    int ret = system("winget install --id SoftwareFreedomConservancy.QEMU "
                     "--accept-source-agreements --accept-package-agreements "
                     "--silent 2>nul");
    if (ret == 0) {
        on_progress({{"status", "installing"}, {"progress", 90},
                     {"log", "QEMU installed via winget"}});
        auto check = find_qemu();
        if (check.ok()) {
            on_progress({{"status", "complete"}, {"progress", 100},
                         {"log", "QEMU ready at " + check.value()}});
            return check.value();
        }
    }

    // Try choco as fallback
    on_progress({{"status", "installing"}, {"progress", 50},
                 {"log", "winget failed, trying chocolatey..."}});
    ret = system("choco install qemu -y --no-progress 2>nul");
    if (ret == 0) {
        on_progress({{"status", "installing"}, {"progress", 90},
                     {"log", "QEMU installed via chocolatey"}});
        auto check = find_qemu();
        if (check.ok()) {
            on_progress({{"status", "complete"}, {"progress", 100},
                         {"log", "QEMU ready at " + check.value()}});
            return check.value();
        }
    }

    on_progress({{"status", "error"}, {"progress", 0},
                 {"log", "Automatic QEMU install failed. Please install manually from https://www.qemu.org/download/#windows"}});
    return Error{"QEMU installation failed on Windows", "INSTALL_FAILED"};

#elif defined(__APPLE__)
    on_progress({{"status", "installing"}, {"progress", 15},
                 {"log", "Installing QEMU via Homebrew..."}});

    int ret = run_command({"brew", "install", "qemu"});
    if (ret == 0) {
        auto check = find_qemu();
        if (check.ok()) {
            on_progress({{"status", "complete"}, {"progress", 100},
                         {"log", "QEMU ready at " + check.value()}});
            return check.value();
        }
    }

    on_progress({{"status", "error"}, {"progress", 0},
                 {"log", "brew install qemu failed. Ensure Homebrew is installed."}});
    return Error{"QEMU installation failed on macOS", "INSTALL_FAILED"};

#else
    // Linux: try apt, dnf, pacman
    on_progress({{"status", "installing"}, {"progress", 15},
                 {"log", "Detecting Linux package manager..."}});

    // Try apt (Debian/Ubuntu)
    if (std::filesystem::exists("/usr/bin/apt-get")) {
        on_progress({{"status", "installing"}, {"progress", 20},
                     {"log", "Using apt-get to install qemu-system-x86..."}});
        int ret = run_command({"sudo", "apt-get", "install", "-y",
                               "qemu-system-x86", "qemu-utils"});
        if (ret == 0) {
            auto check = find_qemu();
            if (check.ok()) {
                on_progress({{"status", "complete"}, {"progress", 100},
                             {"log", "QEMU ready at " + check.value()}});
                return check.value();
            }
        }
    }

    // Try dnf (Fedora/RHEL)
    if (std::filesystem::exists("/usr/bin/dnf")) {
        on_progress({{"status", "installing"}, {"progress", 20},
                     {"log", "Using dnf to install qemu-system-x86..."}});
        int ret = run_command({"sudo", "dnf", "install", "-y",
                               "qemu-system-x86", "qemu-img"});
        if (ret == 0) {
            auto check = find_qemu();
            if (check.ok()) {
                on_progress({{"status", "complete"}, {"progress", 100},
                             {"log", "QEMU ready at " + check.value()}});
                return check.value();
            }
        }
    }

    // Try pacman (Arch)
    if (std::filesystem::exists("/usr/bin/pacman")) {
        on_progress({{"status", "installing"}, {"progress", 20},
                     {"log", "Using pacman to install qemu-full..."}});
        int ret = run_command({"sudo", "pacman", "-S", "--noconfirm", "qemu-full"});
        if (ret == 0) {
            auto check = find_qemu();
            if (check.ok()) {
                on_progress({{"status", "complete"}, {"progress", 100},
                             {"log", "QEMU ready at " + check.value()}});
                return check.value();
            }
        }
    }

    on_progress({{"status", "error"}, {"progress", 0},
                 {"log", "Auto-install failed. Install QEMU manually: apt install qemu-system-x86 qemu-utils"}});
    return Error{"QEMU installation failed on Linux", "INSTALL_FAILED"};
#endif
}

Result<std::string> VmInstaller::download_file(
    const std::string& url,
    const std::string& dest_path,
    const std::string& image_id,
    ProgressCallback on_progress,
    std::atomic<bool>& cancel) {

    ensure_curl();

    // Create temp file path — rename on completion for atomicity
    auto temp_path = dest_path + ".part";

    std::ofstream file(temp_path, std::ios::binary);
    if (!file) {
        return Error{"Failed to create file: " + temp_path, "IO_ERROR"};
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        return Error{"Failed to initialize CURL", "CURL_INIT"};
    }

    DownloadContext ctx;
    ctx.file = &file;
    ctx.on_progress = &on_progress;
    ctx.image_id = image_id;
    ctx.cancel = &cancel;
    ctx.total_bytes = 0;
    ctx.downloaded_bytes = 0;
    ctx.last_percent = -1;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, download_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, download_progress_cb);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ShieldTier/2.0");
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);   // 1KB/s minimum
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30L);      // for 30 seconds
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    // No timeout on total transfer — images can be large
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0L);

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    file.close();

    if (cancel.load()) {
        std::filesystem::remove(temp_path);
        return Error{"Download cancelled", "CANCELLED"};
    }

    if (res != CURLE_OK) {
        std::filesystem::remove(temp_path);
        return Error{std::string("Download failed: ") + curl_easy_strerror(res),
                     "CURL_" + std::to_string(static_cast<int>(res))};
    }

    if (http_code < 200 || http_code >= 300) {
        std::filesystem::remove(temp_path);
        return Error{"HTTP " + std::to_string(http_code), "HTTP_ERROR"};
    }

    // Atomic rename
    std::error_code ec;
    std::filesystem::rename(temp_path, dest_path, ec);
    if (ec) {
        std::filesystem::remove(temp_path);
        return Error{"Failed to rename downloaded file: " + ec.message(), "RENAME_ERROR"};
    }

    return dest_path;
}

Result<std::string> VmInstaller::download_image(
    const VmImageSpec& spec,
    ProgressCallback on_progress,
    std::atomic<bool>& cancel) {

    auto dest = image_path(spec.id);

    // Already downloaded?
    if (std::filesystem::exists(dest)) {
        auto file_size = std::filesystem::file_size(dest);
        // If expected size known and matches, skip
        if (spec.size_bytes <= 0 || static_cast<int64_t>(file_size) >= spec.size_bytes) {
            on_progress({{"imageId", spec.id}, {"status", "complete"},
                         {"progress", 100}, {"downloadedMB", 0}, {"totalMB", 0}});
            return dest;
        }
        // Partial/corrupt — remove and re-download
        std::filesystem::remove(dest);
    }

    on_progress({{"imageId", spec.id}, {"status", "downloading"},
                 {"progress", 0}, {"downloadedMB", 0}, {"totalMB", 0}});

    auto result = download_file(spec.url, dest, spec.id, on_progress, cancel);
    if (!result.ok()) {
        on_progress({{"imageId", spec.id}, {"status", "error"},
                     {"progress", 0}, {"error", result.error().message}});
        return result.error();
    }

    on_progress({{"imageId", spec.id}, {"status", "complete"}, {"progress", 100},
                 {"downloadedMB", 0}, {"totalMB", 0}});
    return dest;
}

std::vector<VmImageSpec> VmInstaller::default_image_catalog() {
    return {
        {
            "alpine-3.19",
            "Alpine Linux 3.19",
            "linux",
            "https://img.socbrowser.com/vm/alpine-3.19.qcow2",
            85 * 1024 * 1024,  // ~85MB
            ""
        },
        {
            "reactos-0.4.15",
            "ReactOS 0.4.15",
            "windows",
            "https://img.socbrowser.com/vm/reactos-0.4.15.qcow2",
            200 * 1024 * 1024,  // ~200MB
            ""
        }
    };
}

std::string VmInstaller::image_path(const std::string& image_id) const {
    return images_dir_ + "/" + image_id + ".qcow2";
}

bool VmInstaller::is_image_downloaded(const std::string& image_id) const {
    auto path = image_path(image_id);
    return std::filesystem::exists(path) && std::filesystem::file_size(path) > 0;
}

}  // namespace shieldtier
