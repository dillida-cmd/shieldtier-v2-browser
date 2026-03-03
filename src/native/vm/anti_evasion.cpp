#include "vm/anti_evasion.h"

#include <cassert>
#include <random>
#include <sstream>

namespace shieldtier {

namespace {

std::mt19937& rng() {
    static thread_local std::mt19937 gen(std::random_device{}());
    return gen;
}

std::string random_hex(int length) {
    static constexpr char hex_chars[] = "0123456789ABCDEF";
    std::uniform_int_distribution<int> dist(0, 15);
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i) {
        result += hex_chars[dist(rng())];
    }
    return result;
}

std::string random_alnum(int length) {
    static constexpr char chars[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::uniform_int_distribution<int> dist(0, 61);
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i) {
        result += chars[dist(rng())];
    }
    return result;
}

std::string random_guid() {
    static constexpr char variant_chars[] = "89AB";
    std::uniform_int_distribution<int> var_dist(0, 3);
    return random_hex(8) + "-" + random_hex(4) + "-" +
           "4" + random_hex(3) + "-" +
           std::string(1, variant_chars[var_dist(rng())]) + random_hex(3) + "-" +
           random_hex(12);
}

template <typename T>
const T& random_choice(const std::vector<T>& items) {
    assert(!items.empty());
    std::uniform_int_distribution<size_t> dist(0, items.size() - 1);
    return items[dist(rng())];
}

struct VendorInfo {
    std::string manufacturer;
    std::string product;
    std::string oui;  // first 3 bytes of MAC as "XX:XX:XX"
};

const std::vector<VendorInfo>& vendor_table() {
    static const std::vector<VendorInfo> table = {
        {"Dell Inc.", "OptiPlex 7090", "00:14:22"},
        {"Dell Inc.", "Latitude 5520", "00:14:22"},
        {"HP", "ProDesk 400 G7", "00:1A:4B"},
        {"HP", "EliteBook 840 G8", "00:1A:4B"},
        {"Lenovo", "ThinkPad T14 Gen 2", "00:50:04"},
        {"Lenovo", "ThinkCentre M70q", "00:50:04"},
        {"ASUSTeK Computer Inc.", "PRIME B560M-A", "04:D4:C4"},
        {"Acer", "Aspire TC-1660", "98:29:A6"},
        {"MSI", "PRO Z690-A", "00:D8:61"},
    };
    return table;
}

const std::vector<std::string>& bios_vendors() {
    static const std::vector<std::string> vendors = {
        "Dell Inc.", "HP", "Lenovo", "ASUS", "Acer", "MSI"
    };
    return vendors;
}

const std::vector<std::string>& fake_programs() {
    static const std::vector<std::string> programs = {
        "Google Chrome", "Microsoft Office Professional Plus 2021",
        "Slack", "Spotify", "Adobe Acrobat Reader DC",
        "7-Zip", "Notepad++", "Visual Studio Code",
        "Zoom", "WinRAR", "VLC media player",
        "Microsoft Teams", "Firefox", "Dropbox",
    };
    return programs;
}

const std::vector<std::string>& fake_processes() {
    static const std::vector<std::string> processes = {
        "chrome.exe", "slack.exe", "outlook.exe", "spotify.exe",
        "teams.exe", "code.exe", "explorer.exe", "taskhostw.exe",
        "svchost.exe", "RuntimeBroker.exe", "SearchApp.exe",
        "OneDrive.exe"
    };
    return processes;
}

const std::vector<std::string>& fake_documents() {
    static const std::vector<std::string> docs = {
        "C:\\Users\\User\\Documents\\Q4 Report.xlsx",
        "C:\\Users\\User\\Documents\\Meeting Notes.docx",
        "C:\\Users\\User\\Documents\\Project Plan.pdf",
        "C:\\Users\\User\\Downloads\\invoice_2024.pdf",
        "C:\\Users\\User\\Downloads\\setup.exe",
        "C:\\Users\\User\\Desktop\\todo.txt",
        "C:\\Users\\User\\Desktop\\budget.xlsx",
        "C:\\Users\\User\\Pictures\\vacation_001.jpg",
    };
    return docs;
}

const std::vector<std::string>& fake_bash_history() {
    static const std::vector<std::string> cmds = {
        "ls -la", "cd ~/Documents", "vim config.yaml",
        "git pull origin main", "docker ps", "sudo apt update",
        "cat /var/log/syslog | tail -50", "ssh dev-server",
        "python3 script.py", "curl https://api.example.com/health",
        "npm install", "make -j8", "top", "df -h",
    };
    return cmds;
}

}  // namespace

AntiEvasion::AntiEvasion(const AntiEvasionConfig& config) : config_(config) {
    const auto& vendor = random_choice(vendor_table());
    selected_manufacturer_ = vendor.manufacturer;
    selected_product_ = vendor.product;
    selected_oui_ = vendor.oui;
}

std::vector<std::string> AntiEvasion::get_qemu_args() const {
    std::vector<std::string> args;

    if (config_.mask_cpuid) {
        args.push_back("-cpu");
        args.push_back("host,-hypervisor");
    }

    if (config_.randomize_mac) {
        args.push_back("-device");
        args.push_back("e1000,mac=" + generate_mac());
    }

    if (config_.randomize_serial) {
        args.push_back("-smbios");
        args.push_back("type=1,serial=" + generate_serial() +
                       ",manufacturer=" + selected_manufacturer_ +
                       ",product=" + selected_product_);
    }

    if (config_.realistic_disk_size) {
        args.push_back("-smbios");
        args.push_back("type=17,size=8192");
    }

    return args;
}

json AntiEvasion::get_guest_patches(const std::string& platform) const {
    json patches;

    if (platform == "windows") {
        json registry_patches = json::array();

        if (config_.add_fake_processes) {
            for (const auto& program : fake_programs()) {
                std::string guid = random_guid();
                registry_patches.push_back({
                    {"path", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{" + guid + "}"},
                    {"name", "DisplayName"},
                    {"type", "REG_SZ"},
                    {"value", program}
                });
            }
        }

        if (config_.randomize_serial) {
            registry_patches.push_back({
                {"path", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum\\0"},
                {"name", "0"},
                {"type", "REG_SZ"},
                {"value", "IDE\\Disk" + selected_manufacturer_ + "_" + generate_serial() + "\\1"}
            });
            registry_patches.push_back({
                {"path", "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS"},
                {"name", "SystemManufacturer"},
                {"type", "REG_SZ"},
                {"value", selected_manufacturer_}
            });
            registry_patches.push_back({
                {"path", "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS"},
                {"name", "SystemProductName"},
                {"type", "REG_SZ"},
                {"value", selected_product_}
            });
        }

        if (config_.set_realistic_uptime) {
            std::uniform_int_distribution<int> dist(86400, 604800);
            registry_patches.push_back({
                {"path", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows"},
                {"name", "ShutdownTime"},
                {"type", "REG_QWORD"},
                {"value", std::to_string(dist(rng()))}
            });
        }

        patches["registry_patches"] = registry_patches;
        patches["filesystem_patches"] = fake_documents();

        if (config_.add_fake_processes) {
            patches["process_patches"] = fake_processes();
        }

    } else if (platform == "linux") {
        std::string hostname = "ws-" + random_alnum(6);

        json filesystem_patches = json::array();
        filesystem_patches.push_back({
            {"path", "/etc/hostname"},
            {"content", hostname}
        });

        std::string history;
        for (const auto& cmd : fake_bash_history()) {
            history += cmd + "\n";
        }
        filesystem_patches.push_back({
            {"path", "/home/user/.bash_history"},
            {"content", history}
        });

        filesystem_patches.push_back({
            {"path", "/sys/class/dmi/id/sys_vendor"},
            {"content", selected_manufacturer_}
        });
        filesystem_patches.push_back({
            {"path", "/sys/class/dmi/id/product_name"},
            {"content", selected_product_}
        });

        patches["filesystem_patches"] = filesystem_patches;
        patches["registry_patches"] = json::array();
        patches["process_patches"] = json::array();
    }

    return patches;
}

std::string AntiEvasion::generate_serial() const {
    return random_alnum(10);
}

std::string AntiEvasion::generate_mac() const {
    std::string mac = selected_oui_;
    for (int i = 0; i < 3; ++i) {
        mac += ":" + random_hex(2);
    }
    return mac;
}

std::string AntiEvasion::generate_bios_vendor() const {
    return random_choice(bios_vendors());
}

}  // namespace shieldtier
