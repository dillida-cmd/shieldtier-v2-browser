---
name: Phantom
description: Use when building the QEMU VM sandbox — VM lifecycle, hypervisor integration (HVF/KVM/WHPX), agentless VMI via EPT hooks, INetSim fake services (DNS/HTTP/HTTPS/SMTP/FTP), anti-evasion (CPUID/TSC masking), Go agent improvements, and multi-VM orchestration
---

# S8 — Phantom: VM Sandbox — QEMU + Hypervisor + VMI + INetSim

## Overview

The longest and most complex agent. Upgrades V1's partially-implemented VM sandbox to a production-grade analysis environment. Fixes broken ETW/process monitoring, adds agentless VMI, direct hypervisor control, full INetSim network simulation, and comprehensive anti-evasion.

## Dependencies

- **Requires:** S0 (foundation), S1 (CEF shell running)
- **No blocking dependencies** on other analysis agents
- **Longest agent:** 15 days Claude / 8 weeks human

## File Ownership

```
src/native/vm/
  manager.cpp/.h            (VM lifecycle management)
  orchestrator.cpp/.h       (multi-VM orchestration, comparative analysis)
  qemu_args.cpp/.h          (QEMU command-line builder)
  qemu_installer.cpp/.h     (QEMU detection/download)
  image_builder.cpp/.h      (golden image creation, unattended install)
  agent_builder.cpp/.h      (Go agent compilation for guest)
  agent_provisioner.cpp/.h  (agent delivery via 9p/VVFAT)
  serial_console.cpp/.h     (virtio-serial NDJSON protocol)
  scoring.cpp/.h            (VM behavioral scoring)
  protocol.cpp/.h           (agent ↔ host message protocol)
  types.h                   (VM-specific types)

  inetsim_server.cpp/.h     (unified fake internet services)
  hypervisor_hvf.cpp/.h     (macOS Hypervisor.framework)
  hypervisor_kvm.cpp/.h     (Linux KVM ioctl)
  hypervisor_whpx.cpp/.h    (Windows WHPX)
  vmi_engine.cpp/.h         (agentless VMI via EPT hooks)
  anti_evasion.cpp/.h       (CPUID masking, TSC offset, env realism)

agents/vm-agent/             (improved Go agent)
  internal/monitor/
    linux/procmon.go         (proc_connector instead of /proc polling)
    windows/etw.go           (real ETW instead of WMIC)
```

## Exit Criteria

Boot VM, inject sample, agentless monitoring (Linux), improved agent (Windows), INetSim DNS+HTTP+SMTP+FTP+HTTPS, anti-evasion passes CPUID/timing/environment checks. Multi-VM comparative analysis across OS versions.

---

## QEMU Command-Line Builder

```cpp
struct QemuConfig {
    std::string machine = "q35";
    std::string cpu = "host,kvm=off";  // hide KVM from guest
    int memory_mb = 4096;
    int cores = 4;
    std::string disk_image;             // qcow2 path
    std::string snapshot_name;          // loadvm snapshot
    std::string qmp_socket;             // QMP control socket
    std::string serial_socket;          // virtio-serial socket
    std::string net_tap_ifname;         // TAP interface for INetSim routing
    bool restrict_network = true;       // block real internet
    bool snapshot_mode = true;          // -snapshot (discard disk writes)
};

std::vector<std::string> build_qemu_args(const QemuConfig& config) {
    std::vector<std::string> args = {
        "qemu-system-x86_64",
        "-machine", config.machine + ",accel=kvm",
        "-cpu", config.cpu,
        "-m", std::to_string(config.memory_mb),
        "-smp", std::to_string(config.cores),
        "-drive", "file=" + config.disk_image + ",format=qcow2,if=virtio",
        "-display", "none",
        "-qmp", "unix:" + config.qmp_socket + ",server,nowait",
    };

    // Virtio-serial for agent communication
    args.insert(args.end(), {
        "-device", "virtio-serial",
        "-chardev", "socket,id=agent,path=" + config.serial_socket + ",server,nowait",
        "-device", "virtserialport,chardev=agent,name=shieldtier.agent.0",
    });

    // Network: route through INetSim, block real internet
    if (config.restrict_network) {
        args.insert(args.end(), {
            "-netdev", "tap,id=net0,ifname=" + config.net_tap_ifname +
                       ",script=no,downscript=no,restrict=on",
            "-device", "virtio-net-pci,netdev=net0,mac=" + random_realistic_mac(),
        });
    }

    if (config.snapshot_mode) args.push_back("-snapshot");
    if (!config.snapshot_name.empty()) {
        args.insert(args.end(), {"-loadvm", config.snapshot_name});
    }

    return args;
}
```

## QMP Client (QEMU Machine Protocol)

```cpp
class QmpClient {
    int sock_fd_ = -1;

public:
    bool connect(const std::string& socket_path) {
        sock_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
        if (::connect(sock_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) return false;

        // Read QMP greeting
        auto greeting = read_json();
        // Negotiate capabilities
        send_json({{"execute", "qmp_capabilities"}});
        read_json(); // response
        return true;
    }

    nlohmann::json execute(const std::string& command,
                            const nlohmann::json& args = {}) {
        nlohmann::json cmd = {{"execute", command}};
        if (!args.empty()) cmd["arguments"] = args;
        send_json(cmd);
        return read_json();
    }

    void save_snapshot(const std::string& name) {
        execute("human-monitor-command",
                {{"command-line", "savevm " + name}});
    }

    void load_snapshot(const std::string& name) {
        execute("human-monitor-command",
                {{"command-line", "loadvm " + name}});
    }

    void screendump(const std::string& path) {
        execute("screendump", {{"filename", path}});
    }
};
```

## INetSim — Fake Internet Services

### DNS Server (UDP 53)

```cpp
class FakeDnsServer {
    int sock_fd_;
    std::string fake_ip_;  // all queries resolve to this IP
    std::vector<DnsQuery> captured_queries_;

public:
    void start(const std::string& bind_addr, uint16_t port, const std::string& fake_ip) {
        fake_ip_ = fake_ip;
        sock_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        // bind to bind_addr:port

        while (running_) {
            uint8_t buf[512];
            struct sockaddr_in client{};
            socklen_t client_len = sizeof(client);
            ssize_t n = recvfrom(sock_fd_, buf, sizeof(buf), 0,
                                  (struct sockaddr*)&client, &client_len);

            auto query = parse_dns_query(buf, n);
            captured_queries_.push_back(query);

            // Check for DNS tunneling
            if (query.domain.size() > 50 || string_entropy(query.domain) > 4.0) {
                // Flag as potential DNS tunneling
            }

            // Build A record response pointing to fake_ip_
            auto response = build_dns_response(buf, n, fake_ip_);
            sendto(sock_fd_, response.data(), response.size(), 0,
                   (struct sockaddr*)&client, client_len);
        }
    }
};
```

### HTTPS Server with Auto-Generated Certs

```cpp
class FakeHttpsServer {
    SSL_CTX* ctx_;
    EVP_PKEY* ca_key_;
    X509* ca_cert_;

    // Generate self-signed CA at startup
    void init_ca() {
        ca_key_ = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key_ex(/*bits=*/2048, ...);
        EVP_PKEY_assign_RSA(ca_key_, rsa);

        ca_cert_ = X509_new();
        X509_set_version(ca_cert_, 2);
        // ... set subject, issuer, validity ...
        X509_sign(ca_cert_, ca_key_, EVP_sha256());
    }

    // Generate per-hostname cert on-the-fly using SNI
    X509* generate_cert_for_host(const std::string& hostname) {
        X509* cert = X509_new();
        // Set subject CN = hostname
        // Add SAN extension for hostname
        // Sign with CA key
        X509_sign(cert, ca_key_, EVP_sha256());
        return cert;
    }

    // SNI callback — select cert based on requested hostname
    static int sni_callback(SSL* ssl, int* alert, void* arg) {
        auto* server = static_cast<FakeHttpsServer*>(arg);
        const char* hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (hostname) {
            X509* cert = server->generate_cert_for_host(hostname);
            SSL_use_certificate(ssl, cert);
            SSL_use_PrivateKey(ssl, server->ca_key_);
        }
        return SSL_TLSEXT_ERR_OK;
    }
};
```

### SMTP Server (TCP 25/587)

```cpp
class FakeSmtpServer {
    struct CapturedEmail {
        std::string from;
        std::vector<std::string> to;
        std::string data;  // raw MIME body
    };
    std::vector<CapturedEmail> captured_;

    void handle_client(int client_fd) {
        send_line(client_fd, "220 mail.example.com ESMTP ready");
        CapturedEmail email;
        std::string state = "INIT";

        while (auto line = read_line(client_fd)) {
            if (starts_with(*line, "EHLO") || starts_with(*line, "HELO")) {
                send_line(client_fd, "250 OK");
            } else if (starts_with(*line, "MAIL FROM:")) {
                email.from = extract_email_address(*line);
                send_line(client_fd, "250 OK");
            } else if (starts_with(*line, "RCPT TO:")) {
                email.to.push_back(extract_email_address(*line));
                send_line(client_fd, "250 OK");
            } else if (*line == "DATA") {
                send_line(client_fd, "354 End data with <CR><LF>.<CR><LF>");
                state = "DATA";
            } else if (state == "DATA") {
                if (*line == ".") {
                    captured_.push_back(email);
                    send_line(client_fd, "250 OK: Message accepted");
                    state = "INIT";
                } else {
                    email.data += *line + "\r\n";
                }
            } else if (starts_with(*line, "QUIT")) {
                send_line(client_fd, "221 Bye");
                break;
            }
        }
    }
};
```

## Hypervisor Abstraction

```cpp
// Cross-platform hypervisor interface
class Hypervisor {
public:
    virtual ~Hypervisor() = default;
    virtual bool create_vm() = 0;
    virtual bool map_memory(void* host_addr, uint64_t guest_addr,
                            size_t size, int flags) = 0;
    virtual bool create_vcpu() = 0;
    virtual VmExitInfo run() = 0;
    virtual bool get_registers(VcpuRegisters& regs) = 0;
    virtual bool set_registers(const VcpuRegisters& regs) = 0;
    virtual bool hide_hypervisor() = 0;  // mask CPUID
    virtual bool enable_dirty_tracking() = 0;
    virtual std::vector<uint64_t> get_dirty_pages() = 0;
};

// Platform factory
std::unique_ptr<Hypervisor> create_hypervisor() {
#if defined(__APPLE__)
    return std::make_unique<HvfHypervisor>();
#elif defined(__linux__)
    return std::make_unique<KvmHypervisor>();
#elif defined(_WIN32)
    return std::make_unique<WhpxHypervisor>();
#endif
}
```

### macOS Hypervisor.framework

```cpp
#include <Hypervisor/hv.h>

class HvfHypervisor : public Hypervisor {
    hv_vcpu_t vcpu_;

    bool create_vm() override {
        return hv_vm_create(HV_VM_DEFAULT) == HV_SUCCESS;
    }

    bool hide_hypervisor() override {
        // Intercept CPUID exits and mask hypervisor bit
        // When guest executes CPUID leaf 1:
        //   Clear ECX bit 31 (hypervisor present)
        // When guest executes CPUID leaf 0x40000000:
        //   Return zeros (no hypervisor vendor string)
        return true;
    }
};
```

### Linux KVM

```cpp
class KvmHypervisor : public Hypervisor {
    int kvm_fd_, vm_fd_, vcpu_fd_;

    bool create_vm() override {
        kvm_fd_ = open("/dev/kvm", O_RDWR);
        vm_fd_ = ioctl(kvm_fd_, KVM_CREATE_VM, 0);
        return vm_fd_ >= 0;
    }

    bool hide_hypervisor() override {
        // KVM_SET_CPUID2 — modify CPUID entries
        struct kvm_cpuid2* cpuid = /* fetch KVM_GET_SUPPORTED_CPUID */;
        for (int i = 0; i < cpuid->nent; i++) {
            if (cpuid->entries[i].function == 1) {
                cpuid->entries[i].ecx &= ~(1 << 31);  // clear hypervisor bit
            }
            if (cpuid->entries[i].function == 0x40000000) {
                cpuid->entries[i].eax = 0;  // no hypervisor leaves
                cpuid->entries[i].ebx = 0;
                cpuid->entries[i].ecx = 0;
                cpuid->entries[i].edx = 0;
            }
        }
        ioctl(vcpu_fd_, KVM_SET_CPUID2, cpuid);
        return true;
    }

    bool enable_dirty_tracking() override {
        // Enable KVM_MEM_LOG_DIRTY_PAGES on memory slots
        return true;
    }

    std::vector<uint64_t> get_dirty_pages() override {
        struct kvm_dirty_log dirty{};
        dirty.slot = 0;
        // ... allocate bitmap, ioctl KVM_GET_DIRTY_LOG ...
        std::vector<uint64_t> pages;
        // iterate bitmap, collect dirty page addresses
        return pages;
    }
};
```

## Anti-Evasion

```cpp
struct AntiEvasionConfig {
    // Hardware masking
    bool mask_cpuid = true;
    bool mask_hypervisor_vendor = true;
    std::string spoofed_mac;          // random realistic vendor prefix
    std::string spoofed_disk_model;   // "Samsung SSD 970 EVO Plus"
    std::string spoofed_bios_vendor;  // "Dell Inc."

    // Timing
    bool offset_tsc = true;

    // Environment realism
    std::string username = "john.mitchell";
    std::string computer_name = "DESKTOP-A8K2JF3";
    std::string locale = "en-US";
    int screen_width = 1920;
    int screen_height = 1080;
};
```

## Go Agent Improvements (V1 Fix)

```go
// Linux: proc_connector instead of /proc polling
// Uses CN_PROC netlink socket for zero-latency process events

func monitorProcesses(events chan<- ProcessEvent) {
    sock, _ := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
    // Subscribe to CN_PROC events
    // Handle PROC_EVENT_FORK, PROC_EVENT_EXEC, PROC_EVENT_EXIT
    // Read /proc/<pid>/cmdline for new processes
}

// Windows: Real ETW instead of WMIC polling
// Uses advapi32 StartTrace + EnableTraceEx2 + ProcessTrace

func monitorETW(events chan<- ProcessEvent) {
    // Open trace session with kernel providers:
    // Microsoft-Windows-Kernel-Process (process create/exit)
    // Microsoft-Windows-Kernel-File (file I/O)
    // Microsoft-Windows-Kernel-Registry (registry changes)
    // Microsoft-Windows-Kernel-Network (network connections)
}
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| QEMU without -restrict=on | Malware reaches real internet — always restrict |
| Not using -snapshot mode | Disk changes persist between analyses — always snapshot |
| INetSim DNS forwarding to 8.8.8.8 in sandbox mode | Never forward in sandbox — resolve all to fake IP |
| Not masking CPUID hypervisor bit | Most basic VM detection catches this — always mask |
| Go agent: WMIC polling for processes | Real ETW on Windows, proc_connector on Linux |
| Scoring events that agents don't produce | Only score events with actual producers |
| Not cleaning up QEMU processes | Always kill QEMU on analysis end, use process groups |
| Same MAC address for all VMs | Each VM needs unique realistic MAC — random vendor prefix |
| Missing INetSim HTTPS cert generation | Malware connecting to HTTPS C2 gets TLS error without per-host certs |
| QMP socket permissions | Ensure socket is writable by ShieldTier process |
