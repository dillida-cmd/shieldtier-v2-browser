# Hypervisor APIs & Network Simulation — Code Reference

Research for ShieldTier V2 VM sandbox subsystem (`src/native/vm/`).

---

## 1. Apple Hypervisor.framework (macOS)

### 1.1 Full Lifecycle

```cpp
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define VM_MEM_SIZE (1 * 1024 * 1024)  // 1 MB guest RAM

// Guest code: writes 0x42 to port 0x10 then halts
static const uint8_t guest_code[] = {
    0xBA, 0x10, 0x00,   // mov dx, 0x10
    0xB0, 0x42,         // mov al, 0x42
    0xEE,               // out dx, al
    0xF4,               // hlt
};

static void check(hv_return_t ret, const char* msg) {
    if (ret != HV_SUCCESS) {
        fprintf(stderr, "FAIL: %s (err=%x)\n", msg, ret);
        exit(1);
    }
}

int main() {
    // Step 1: Create VM
    check(hv_vm_create(HV_VM_DEFAULT), "hv_vm_create");

    // Step 2: Allocate and map guest memory
    void* vm_mem = valloc(VM_MEM_SIZE);
    memset(vm_mem, 0, VM_MEM_SIZE);
    memcpy((uint8_t*)vm_mem + 0x1000, guest_code, sizeof(guest_code));

    check(hv_vm_map(vm_mem, 0x0, VM_MEM_SIZE,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC),
          "hv_vm_map");

    // Step 3: Create vCPU
    hv_vcpuid_t vcpu;
    check(hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT), "hv_vcpu_create");

    // Step 4: Initialize VMCS guest state — real mode
    // Control fields
    uint64_t cap_pinbased, cap_procbased, cap_procbased2, cap_entry, cap_exit;
    hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &cap_pinbased);
    hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &cap_procbased);
    hv_vmx_read_capability(HV_VMX_CAP_PROCBASED2, &cap_procbased2);
    hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &cap_entry);
    hv_vmx_read_capability(HV_VMX_CAP_EXIT, &cap_exit);

    // Pin-based: required bits only
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_PIN_BASED,
        cap2ctrl(cap_pinbased, 0));
    // Proc-based: unconditional I/O exiting
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CPU_BASED,
        cap2ctrl(cap_procbased, CPU_BASED_HLT | CPU_BASED_IO));
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CPU_BASED2,
        cap2ctrl(cap_procbased2, 0));
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS,
        cap2ctrl(cap_entry, 0));
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_VMEXIT_CONTROLS,
        cap2ctrl(cap_exit, 0));

    // Segment registers — 16-bit real mode
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_SELECTOR, 0x0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_BASE, 0x0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xFFFF);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_AR, 0x9B);

    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_SELECTOR, 0x0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_BASE, 0x0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xFFFF);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_AR, 0x93);

    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_SELECTOR, 0x0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_BASE, 0x0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xFFFF);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_AR, 0x93);

    // CR0: PE=0 (real mode), ET=1 (x87 present)
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR0, 0x20);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR4, 0x2000); // VMXE

    // RIP = 0x1000 (where guest code lives)
    hv_vcpu_write_register(vcpu, HV_X86_RIP, 0x1000);
    hv_vcpu_write_register(vcpu, HV_X86_RSP, 0xFFFC);
    hv_vcpu_write_register(vcpu, HV_X86_RFLAGS, 0x2);

    // Step 5: Run loop — handle VMexits
    for (;;) {
        check(hv_vcpu_run(vcpu), "hv_vcpu_run");

        uint64_t exit_reason;
        hv_vmx_vcpu_read_vmcs(vcpu, VMCS_EXIT_REASON, &exit_reason);

        switch (exit_reason) {
        case VMX_REASON_IO: {
            uint64_t qual;
            hv_vmx_vcpu_read_vmcs(vcpu, VMCS_EXIT_QUALIFICATION, &qual);
            uint16_t port = (qual >> 16) & 0xFFFF;
            bool is_out = !(qual & 8);
            uint64_t rax;
            hv_vcpu_read_register(vcpu, HV_X86_RAX, &rax);

            if (is_out && port == 0x10) {
                printf("Guest wrote 0x%02llx to port 0x%x\n",
                       rax & 0xFF, port);
            }

            // Advance RIP past the I/O instruction
            uint64_t rip;
            uint64_t insn_len;
            hv_vmx_vcpu_read_vmcs(vcpu, VMCS_EXIT_INSTRUCTION_LENGTH,
                                  &insn_len);
            hv_vcpu_read_register(vcpu, HV_X86_RIP, &rip);
            hv_vcpu_write_register(vcpu, HV_X86_RIP, rip + insn_len);
            break;
        }
        case VMX_REASON_HLT:
            printf("Guest halted.\n");
            goto done;

        case VMX_REASON_EPT_VIOLATION: {
            uint64_t gpa;
            hv_vmx_vcpu_read_vmcs(vcpu, VMCS_GUEST_PHYSICAL_ADDRESS, &gpa);
            printf("EPT violation at GPA 0x%llx\n", gpa);
            goto done;
        }
        default:
            printf("Unhandled VMexit reason: %llu\n", exit_reason);
            goto done;
        }
    }

done:
    hv_vcpu_destroy(vcpu);
    hv_vm_destroy();
    free(vm_mem);
    return 0;
}
```

Helper for capability bits (from xhyve):

```cpp
static uint64_t cap2ctrl(uint64_t cap, uint64_t ctrl) {
    // bits 0-31: allowed 0-settings
    // bits 32-63: allowed 1-settings
    return (ctrl | (cap & 0xFFFFFFFF)) & (cap >> 32);
}
```

### 1.2 Register Read/Write

```cpp
// Write general-purpose registers
hv_vcpu_write_register(vcpu, HV_X86_RAX, 0);
hv_vcpu_write_register(vcpu, HV_X86_RBX, 0);
hv_vcpu_write_register(vcpu, HV_X86_RCX, 0);
hv_vcpu_write_register(vcpu, HV_X86_RDX, 0);
hv_vcpu_write_register(vcpu, HV_X86_RSI, 0);
hv_vcpu_write_register(vcpu, HV_X86_RDI, 0);
hv_vcpu_write_register(vcpu, HV_X86_RSP, 0xFFFC);
hv_vcpu_write_register(vcpu, HV_X86_RBP, 0);
hv_vcpu_write_register(vcpu, HV_X86_RIP, entry_point);
hv_vcpu_write_register(vcpu, HV_X86_RFLAGS, 0x2);

// Read registers after VMexit
uint64_t rax, rip, rsp;
hv_vcpu_read_register(vcpu, HV_X86_RAX, &rax);
hv_vcpu_read_register(vcpu, HV_X86_RIP, &rip);
hv_vcpu_read_register(vcpu, HV_X86_RSP, &rsp);

// VMCS fields (not general registers — accessed differently)
uint64_t cr0, cr3, cr4;
hv_vmx_vcpu_read_vmcs(vcpu, VMCS_GUEST_CR0, &cr0);
hv_vmx_vcpu_read_vmcs(vcpu, VMCS_GUEST_CR3, &cr3);
hv_vmx_vcpu_read_vmcs(vcpu, VMCS_GUEST_CR4, &cr4);
```

### 1.3 CPUID Masking (Hypervisor.framework)

Apple's Hypervisor.framework does not expose a direct CPUID filter API like KVM's `KVM_SET_CPUID2`. CPUID instructions from the guest cause a VMexit with reason `VMX_REASON_CPUID`. You intercept and emulate:

```cpp
case VMX_REASON_CPUID: {
    uint64_t rax, rcx;
    hv_vcpu_read_register(vcpu, HV_X86_RAX, &rax);
    hv_vcpu_read_register(vcpu, HV_X86_RCX, &rcx);

    uint32_t leaf = (uint32_t)rax;
    uint32_t subleaf = (uint32_t)rcx;

    // Execute real CPUID on host, then filter
    uint32_t eax, ebx, ecx_out, edx;
    __asm__ volatile("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx_out), "=d"(edx)
        : "a"(leaf), "c"(subleaf));

    if (leaf == 1) {
        // Clear hypervisor present bit (ECX bit 31)
        ecx_out &= ~(1u << 31);
    } else if (leaf == 0x40000000) {
        // Hide hypervisor vendor — return 0 (no hypervisor leaves)
        eax = 0; ebx = 0; ecx_out = 0; edx = 0;
    }

    hv_vcpu_write_register(vcpu, HV_X86_RAX, eax);
    hv_vcpu_write_register(vcpu, HV_X86_RBX, ebx);
    hv_vcpu_write_register(vcpu, HV_X86_RCX, ecx_out);
    hv_vcpu_write_register(vcpu, HV_X86_RDX, edx);

    // Advance past CPUID (2-byte instruction: 0F A2)
    uint64_t rip;
    hv_vcpu_read_register(vcpu, HV_X86_RIP, &rip);
    hv_vcpu_write_register(vcpu, HV_X86_RIP, rip + 2);
    break;
}
```

### 1.4 Entitlements and Linking

Entitlements plist (`ShieldTier.entitlements`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
```

CMake:

```cmake
target_link_libraries(shieldtier_vm PRIVATE "-framework Hypervisor")

# Sign with entitlements (required for Hypervisor.framework)
add_custom_command(TARGET shieldtier_vm POST_BUILD
    COMMAND codesign --force --sign - --entitlements
        ${CMAKE_SOURCE_DIR}/ShieldTier.entitlements
        $<TARGET_FILE:shieldtier_vm>
)
```

---

## 2. Linux KVM

### 2.1 Full Lifecycle

```cpp
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

// Guest code: write 0x42 to port 0x10, then hlt
static const uint8_t guest_code[] = {
    0xBA, 0x10, 0x00,   // mov dx, 0x10
    0xB0, 0x42,         // mov al, 0x42
    0xEE,               // out dx, al
    0xF4,               // hlt
};

int main() {
    // Step 1: Open KVM
    int kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);

    // Verify API version
    int api_ver = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
    if (api_ver != 12) { fprintf(stderr, "KVM API mismatch\n"); return 1; }

    // Step 2: Create VM
    int vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);

    // Step 3: Allocate guest memory and load code
    size_t mem_size = 0x200000; // 2 MB
    void* mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memcpy((uint8_t*)mem + 0x1000, guest_code, sizeof(guest_code));

    // Step 4: Map guest physical memory
    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .flags = 0,
        .guest_phys_addr = 0,
        .memory_size = mem_size,
        .userspace_addr = (uint64_t)mem,
    };
    ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region);

    // Step 5: Create vCPU
    int vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);

    // Step 6: mmap the kvm_run struct
    int run_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    struct kvm_run* run = (struct kvm_run*)mmap(
        NULL, run_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);

    // Step 7: Initialize segment registers (real mode)
    struct kvm_sregs sregs;
    ioctl(vcpu_fd, KVM_GET_SREGS, &sregs);
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    sregs.ds.base = 0;
    sregs.ds.selector = 0;
    sregs.es.base = 0;
    sregs.es.selector = 0;
    sregs.ss.base = 0;
    sregs.ss.selector = 0;
    ioctl(vcpu_fd, KVM_SET_SREGS, &sregs);

    // Step 8: Set general registers
    struct kvm_regs regs = {};
    regs.rip = 0x1000;
    regs.rsp = 0xFFFC;
    regs.rflags = 0x2;
    ioctl(vcpu_fd, KVM_SET_REGS, &regs);

    // Step 9: Run loop
    for (;;) {
        ioctl(vcpu_fd, KVM_RUN, 0);

        switch (run->exit_reason) {
        case KVM_EXIT_IO:
            if (run->io.direction == KVM_EXIT_IO_OUT &&
                run->io.port == 0x10) {
                uint8_t* data = (uint8_t*)run + run->io.data_offset;
                printf("Guest wrote 0x%02x to port 0x%x\n",
                       *data, run->io.port);
            }
            break;

        case KVM_EXIT_HLT:
            printf("Guest halted.\n");
            goto done;

        case KVM_EXIT_SHUTDOWN:
            printf("Guest shutdown.\n");
            goto done;

        case KVM_EXIT_INTERNAL_ERROR:
            printf("KVM internal error: suberror=%d\n",
                   run->internal.suberror);
            goto done;

        default:
            printf("Unhandled exit reason: %d\n", run->exit_reason);
            goto done;
        }
    }

done:
    munmap(run, run_size);
    close(vcpu_fd);
    munmap(mem, mem_size);
    close(vm_fd);
    close(kvm_fd);
    return 0;
}
```

### 2.2 Dirty Page Tracking (KVM_GET_DIRTY_LOG)

```cpp
// Enable dirty page logging on slot 0
struct kvm_userspace_memory_region region = {
    .slot = 0,
    .flags = KVM_MEM_LOG_DIRTY_PAGES,  // enable dirty tracking
    .guest_phys_addr = 0,
    .memory_size = mem_size,
    .userspace_addr = (uint64_t)mem,
};
ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region);

// After running guest, retrieve dirty bitmap
size_t bitmap_size = (mem_size / 4096 + 7) / 8;  // 1 bit per 4K page
uint8_t* dirty_bitmap = (uint8_t*)calloc(1, bitmap_size);

struct kvm_dirty_log dirty_log = {
    .slot = 0,
    .dirty_bitmap = dirty_bitmap,
};
ioctl(vm_fd, KVM_GET_DIRTY_LOG, &dirty_log);

// Check which pages were modified
for (size_t i = 0; i < bitmap_size; i++) {
    for (int bit = 0; bit < 8; bit++) {
        if (dirty_bitmap[i] & (1 << bit)) {
            size_t page_idx = i * 8 + bit;
            uint64_t gpa = page_idx * 4096;
            printf("Dirty page at GPA 0x%lx\n", gpa);
        }
    }
}

free(dirty_bitmap);
```

### 2.3 CPUID Masking (KVM_SET_CPUID2)

```cpp
// Get supported CPUID entries from KVM
struct {
    struct kvm_cpuid2 header;
    struct kvm_cpuid_entry2 entries[256];
} cpuid_data;
cpuid_data.header.nent = 256;
ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, &cpuid_data);

// Modify entries to hide hypervisor
for (uint32_t i = 0; i < cpuid_data.header.nent; i++) {
    struct kvm_cpuid_entry2* e = &cpuid_data.entries[i];

    if (e->function == 1) {
        // Clear hypervisor present bit (ECX.31)
        e->ecx &= ~(1u << 31);
    }

    if (e->function == 0x40000000) {
        // Zero out hypervisor vendor leaves
        e->eax = 0;
        e->ebx = 0;
        e->ecx = 0;
        e->edx = 0;
    }

    if (e->function == 0x40000001) {
        // Zero out KVM feature flags
        e->eax = 0;
        e->edx = 0;
    }
}

// Apply modified CPUID to vCPU
ioctl(vcpu_fd, KVM_SET_CPUID2, &cpuid_data);
```

### 2.4 EPT Violation Trapping for Syscall Hooking

EPT-based syscall hooking uses split TLB technique: make a page executable-only (no read/write) so data reads fault through EPT, giving you a VMexit on every access to that page.

```cpp
// Conceptual flow — requires kernel module or patched KVM

// 1. Identify the guest physical page containing the syscall entry
//    (e.g., LSTAR MSR points to entry_SYSCALL_64)
uint64_t syscall_gpa = /* translate GVA of entry_SYSCALL_64 to GPA */;
uint64_t page_gpa = syscall_gpa & ~0xFFFULL;

// 2. Mark the page execute-only in EPT
//    In the EPT page table entry:
//    - Bit 0 (Read)  = 0
//    - Bit 1 (Write) = 0
//    - Bit 2 (Exec)  = 1
//    This requires EPT execute-only support (IA32_VMX_EPT_VPID_CAP bit 0)

// 3. When the guest reads the syscall dispatch table on that page,
//    an EPT violation VMexit occurs:
//    exit_reason = KVM_EXIT_EPT_VIOLATION
//    The exit qualification tells you:
//    - Was it a read, write, or instruction fetch?
//    - The guest physical address that faulted

// 4. In the VMexit handler:
//    a) Log the syscall number (from guest RAX)
//    b) Temporarily grant read access to the page
//    c) Set the Monitor Trap Flag (MTF) in VMCS
//    d) Resume guest

// 5. After one instruction, MTF fires:
//    a) Remove read access again (re-arm the trap)
//    b) Clear MTF
//    c) Resume guest

// Using KVM-VMI (github.com/KVM-VMI/kvm-vmi) is the practical approach.
// It patches KVM to expose VMI ioctls:
//   KVM_VMI_SET_EPT_PERMISSIONS  — set R/W/X on specific GPA range
//   KVM_VMI_GET_EPT_VIOLATION    — retrieve fault info
```

For production use, the [KVM-VMI project](https://github.com/KVM-VMI/kvm-vmi) patches KVM to expose introspection ioctls. The alternative is [DdiMon](https://github.com/tandasat/DdiMon) approach (inline EPT hooking).

---

## 3. Windows WHPX (Windows Hypervisor Platform)

### 3.1 Full Lifecycle

```cpp
#include <windows.h>
#include <WinHvPlatform.h>
#include <stdio.h>

#pragma comment(lib, "WinHvPlatform.lib")

// Guest code: write 0x42 to port 0x10, then hlt
static const uint8_t guest_code[] = {
    0xBA, 0x10, 0x00,   // mov dx, 0x10
    0xB0, 0x42,         // mov al, 0x42
    0xEE,               // out dx, al
    0xF4,               // hlt
};

int main() {
    HRESULT hr;

    // Step 1: Check capability
    WHV_CAPABILITY cap;
    UINT32 written;
    hr = WHvGetCapability(WHvCapabilityCodeHypervisorPresent,
                          &cap, sizeof(cap), &written);
    if (FAILED(hr) || !cap.HypervisorPresent) {
        printf("Hyper-V not available\n");
        return 1;
    }

    // Step 2: Create partition
    WHV_PARTITION_HANDLE partition;
    hr = WHvCreatePartition(&partition);

    // Step 3: Configure — 1 processor
    WHV_PARTITION_PROPERTY prop = {};
    prop.ProcessorCount = 1;
    hr = WHvSetPartitionProperty(partition,
        WHvPartitionPropertyCodeProcessorCount, &prop, sizeof(prop));

    // Enable I/O port exits
    WHV_PARTITION_PROPERTY exitProp = {};
    exitProp.ExtendedVmExits.X64IoPortExit = 1;
    hr = WHvSetPartitionProperty(partition,
        WHvPartitionPropertyCodeExtendedVmExits,
        &exitProp, sizeof(exitProp));

    // Step 4: Setup partition (finalize config)
    hr = WHvSetupPartition(partition);

    // Step 5: Allocate and map guest memory
    SIZE_T mem_size = 2 * 1024 * 1024;  // 2 MB
    void* mem = VirtualAlloc(NULL, mem_size, MEM_COMMIT, PAGE_READWRITE);
    memcpy((uint8_t*)mem + 0x1000, guest_code, sizeof(guest_code));

    hr = WHvMapGpaRange(partition, mem, 0, mem_size,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite |
        WHvMapGpaRangeFlagExecute);

    // Step 6: Create virtual processor
    hr = WHvCreateVirtualProcessor(partition, 0, 0);

    // Step 7: Set initial registers
    WHV_REGISTER_NAME reg_names[] = {
        WHvX64RegisterRip,
        WHvX64RegisterRsp,
        WHvX64RegisterRflags,
        WHvX64RegisterCs,
        WHvX64RegisterDs,
        WHvX64RegisterSs,
    };

    WHV_REGISTER_VALUE reg_values[6] = {};
    reg_values[0].Reg64 = 0x1000;           // RIP
    reg_values[1].Reg64 = 0xFFFC;           // RSP
    reg_values[2].Reg64 = 0x2;              // RFLAGS

    // CS segment — real mode
    reg_values[3].Segment.Base = 0;
    reg_values[3].Segment.Limit = 0xFFFF;
    reg_values[3].Segment.Selector = 0;
    reg_values[3].Segment.Attributes = 0x9B;

    // DS segment
    reg_values[4].Segment.Base = 0;
    reg_values[4].Segment.Limit = 0xFFFF;
    reg_values[4].Segment.Selector = 0;
    reg_values[4].Segment.Attributes = 0x93;

    // SS segment
    reg_values[5].Segment.Base = 0;
    reg_values[5].Segment.Limit = 0xFFFF;
    reg_values[5].Segment.Selector = 0;
    reg_values[5].Segment.Attributes = 0x93;

    hr = WHvSetVirtualProcessorRegisters(partition, 0,
        reg_names, 6, reg_values);

    // Step 8: Run loop
    WHV_RUN_VP_EXIT_CONTEXT exit_ctx;

    for (;;) {
        hr = WHvRunVirtualProcessor(partition, 0,
            &exit_ctx, sizeof(exit_ctx));

        switch (exit_ctx.ExitReason) {
        case WHvRunVpExitReasonX64IoPortAccess: {
            auto& io = exit_ctx.IoPortAccess;
            if (io.AccessInfo.IsWrite && io.PortNumber == 0x10) {
                printf("Guest wrote 0x%02x to port 0x%x\n",
                       (uint8_t)io.Rax, io.PortNumber);
            }
            // Advance RIP
            WHV_REGISTER_NAME rip_name = WHvX64RegisterRip;
            WHV_REGISTER_VALUE rip_val;
            rip_val.Reg64 = exit_ctx.VpContext.Rip +
                            exit_ctx.VpContext.InstructionLength;
            WHvSetVirtualProcessorRegisters(partition, 0,
                &rip_name, 1, &rip_val);
            break;
        }
        case WHvRunVpExitReasonX64Halt:
            printf("Guest halted.\n");
            goto done;

        default:
            printf("Unhandled exit: %d\n", exit_ctx.ExitReason);
            goto done;
        }
    }

done:
    WHvDeleteVirtualProcessor(partition, 0);
    WHvUnmapGpaRange(partition, 0, mem_size);
    VirtualFree(mem, 0, MEM_RELEASE);
    WHvDeletePartition(partition);
    return 0;
}
```

### 3.2 Dirty Page Tracking

```cpp
// Enable dirty page tracking when mapping memory
hr = WHvMapGpaRange(partition, mem, 0, mem_size,
    WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite |
    WHvMapGpaRangeFlagExecute | WHvMapGpaRangeFlagTrackDirtyPages);

// After running guest, query dirty bitmap
size_t bitmap_size = (mem_size / 4096 + 7) / 8;
// Round up to 8-byte alignment as required by API
bitmap_size = (bitmap_size + 7) & ~7ULL;
uint64_t* bitmap = (uint64_t*)calloc(1, bitmap_size);

hr = WHvQueryGpaRangeDirtyBitmap(partition, 0, mem_size,
                                  bitmap, bitmap_size);
if (SUCCEEDED(hr)) {
    for (size_t i = 0; i < bitmap_size / 8; i++) {
        if (bitmap[i] == 0) continue;
        for (int bit = 0; bit < 64; bit++) {
            if (bitmap[i] & (1ULL << bit)) {
                uint64_t gpa = (i * 64 + bit) * 4096;
                printf("Dirty page at GPA 0x%llx\n", gpa);
            }
        }
    }
}

free(bitmap);
```

---

## 4. INetSim Implementation (C++)

### 4.1 UDP DNS Server

```cpp
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <cmath>

// DNS header per RFC 1035
struct __attribute__((packed)) dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Flag bits
#define DNS_QR_RESPONSE  0x8000
#define DNS_AA           0x0400
#define DNS_RCODE_OK     0x0000
#define DNS_RCODE_NXDOMAIN 0x0003

struct dns_query_result {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;
    size_t offset;  // bytes consumed from packet
};

// Parse QNAME labels: 3www6google3com0 -> "www.google.com"
static dns_query_result parse_question(const uint8_t* buf, size_t len,
                                        size_t offset) {
    dns_query_result result = {};
    std::string name;
    size_t pos = offset;

    while (pos < len) {
        uint8_t label_len = buf[pos++];
        if (label_len == 0) break;

        if (label_len > 63 || pos + label_len > len) {
            result.qname = "INVALID";
            return result;
        }

        if (!name.empty()) name += '.';
        name.append((const char*)&buf[pos], label_len);
        pos += label_len;
    }

    if (pos + 4 <= len) {
        result.qtype  = (buf[pos] << 8) | buf[pos + 1];
        result.qclass = (buf[pos + 2] << 8) | buf[pos + 3];
        pos += 4;
    }

    result.qname = name;
    result.offset = pos - offset;
    return result;
}

// Build A record response: always returns fake_ip
static std::vector<uint8_t> build_response(
    const uint8_t* query, size_t query_len,
    const dns_query_result& q, uint32_t fake_ip)
{
    std::vector<uint8_t> resp(query, query + query_len);

    // Modify header: set QR=1 (response), AA=1, ANCOUNT=1
    dns_header* hdr = (dns_header*)resp.data();
    hdr->flags = htons(DNS_QR_RESPONSE | DNS_AA | DNS_RCODE_OK);
    hdr->ancount = htons(1);

    // Append answer RR
    // Name pointer to QNAME in question section (offset 12)
    resp.push_back(0xC0);
    resp.push_back(0x0C);
    // Type A (1)
    resp.push_back(0x00); resp.push_back(0x01);
    // Class IN (1)
    resp.push_back(0x00); resp.push_back(0x01);
    // TTL = 60 seconds
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x3C);
    // RDLENGTH = 4
    resp.push_back(0x00); resp.push_back(0x04);
    // RDATA = IP address (network byte order)
    resp.push_back((fake_ip >> 24) & 0xFF);
    resp.push_back((fake_ip >> 16) & 0xFF);
    resp.push_back((fake_ip >> 8) & 0xFF);
    resp.push_back(fake_ip & 0xFF);

    return resp;
}

class fake_dns_server {
    int sock_fd_ = -1;
    uint32_t fake_ip_;   // all queries resolve to this
    bool running_ = false;

    // DNS tunneling detection
    struct tunnel_stats {
        uint32_t query_count = 0;
        double total_entropy = 0.0;
        uint32_t txt_count = 0;
        uint32_t long_label_count = 0;
    };
    std::unordered_map<std::string, tunnel_stats> domain_stats_;

public:
    explicit fake_dns_server(const char* fake_ip_str)
        : fake_ip_(ntohl(inet_addr(fake_ip_str))) {}

    bool start(uint16_t port = 53) {
        sock_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_fd_ < 0) return false;

        int reuse = 1;
        setsockopt(sock_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(sock_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock_fd_);
            return false;
        }

        running_ = true;
        return true;
    }

    void run() {
        uint8_t buf[512];
        struct sockaddr_in client_addr;
        socklen_t addr_len;

        while (running_) {
            addr_len = sizeof(client_addr);
            ssize_t n = recvfrom(sock_fd_, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&client_addr, &addr_len);
            if (n < (ssize_t)sizeof(dns_header)) continue;

            dns_header* hdr = (dns_header*)buf;
            if (ntohs(hdr->qdcount) < 1) continue;

            auto q = parse_question(buf, n, sizeof(dns_header));

            // Check for DNS tunneling indicators
            bool tunnel_flag = check_tunneling(q);
            if (tunnel_flag) {
                // Log but still respond (capture behavior)
                // logged via analysis callback
            }

            auto resp = build_response(buf, n, q, fake_ip_);
            sendto(sock_fd_, resp.data(), resp.size(), 0,
                   (struct sockaddr*)&client_addr, addr_len);
        }
    }

    void stop() {
        running_ = false;
        if (sock_fd_ >= 0) { close(sock_fd_); sock_fd_ = -1; }
    }

private:
    // Shannon entropy of a string
    static double shannon_entropy(const std::string& s) {
        if (s.empty()) return 0.0;
        int freq[256] = {};
        for (char c : s) freq[(unsigned char)c]++;
        double entropy = 0.0;
        double len = (double)s.size();
        for (int i = 0; i < 256; i++) {
            if (freq[i] == 0) continue;
            double p = freq[i] / len;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    // Extract registerable domain (last two labels)
    static std::string base_domain(const std::string& qname) {
        auto dot2 = qname.rfind('.');
        if (dot2 == std::string::npos) return qname;
        auto dot1 = qname.rfind('.', dot2 - 1);
        if (dot1 == std::string::npos) return qname;
        return qname.substr(dot1 + 1);
    }

    bool check_tunneling(const dns_query_result& q) {
        // Extract subdomain portion (everything before base domain)
        std::string base = base_domain(q.qname);
        std::string subdomain;
        if (q.qname.size() > base.size() + 1) {
            subdomain = q.qname.substr(0, q.qname.size() - base.size() - 1);
        }

        auto& stats = domain_stats_[base];
        stats.query_count++;

        bool flagged = false;

        // Indicator 1: High entropy subdomain (> 4.0 bits)
        if (!subdomain.empty()) {
            double ent = shannon_entropy(subdomain);
            stats.total_entropy += ent;
            if (ent > 4.0) flagged = true;
        }

        // Indicator 2: Long subdomain labels (> 50 chars)
        if (subdomain.size() > 50) {
            stats.long_label_count++;
            flagged = true;
        }

        // Indicator 3: TXT/NULL/CNAME query types used for exfiltration
        // A=1, CNAME=5, NULL=10, TXT=16, MX=15
        if (q.qtype == 16 || q.qtype == 10 || q.qtype == 5 ||
            q.qtype == 15) {
            stats.txt_count++;
            if (stats.txt_count > 10) flagged = true;
        }

        // Indicator 4: High query volume to single domain
        if (stats.query_count > 100) flagged = true;

        return flagged;
    }
};
```

### 4.2 TCP HTTP Server (Fake Responses by Extension)

```cpp
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <sstream>

class fake_http_server {
    int listen_fd_ = -1;
    bool running_ = false;

    // Content-type map for realistic responses
    static const char* mime_for_ext(const std::string& ext) {
        static const std::unordered_map<std::string, const char*> m = {
            {".html", "text/html"},
            {".htm",  "text/html"},
            {".js",   "application/javascript"},
            {".css",  "text/css"},
            {".json", "application/json"},
            {".xml",  "application/xml"},
            {".txt",  "text/plain"},
            {".png",  "image/png"},
            {".jpg",  "image/jpeg"},
            {".gif",  "image/gif"},
            {".ico",  "image/x-icon"},
            {".pdf",  "application/pdf"},
            {".exe",  "application/octet-stream"},
            {".dll",  "application/octet-stream"},
            {".zip",  "application/zip"},
            {".doc",  "application/msword"},
        };
        auto it = m.find(ext);
        return it != m.end() ? it->second : "text/html";
    }

    static std::string extract_path(const std::string& request) {
        auto sp1 = request.find(' ');
        if (sp1 == std::string::npos) return "/";
        auto sp2 = request.find(' ', sp1 + 1);
        if (sp2 == std::string::npos) return "/";
        std::string path = request.substr(sp1 + 1, sp2 - sp1 - 1);
        auto q = path.find('?');
        if (q != std::string::npos) path = path.substr(0, q);
        return path;
    }

    static std::string extract_extension(const std::string& path) {
        auto dot = path.rfind('.');
        if (dot == std::string::npos) return ".html";
        return path.substr(dot);
    }

    // Generate fake body based on extension
    static std::string fake_body(const std::string& ext) {
        if (ext == ".html" || ext == ".htm") {
            return "<html><head><title>OK</title></head>"
                   "<body><h1>It works</h1></body></html>";
        }
        if (ext == ".js") {
            return "var _=function(){return true;};";
        }
        if (ext == ".css") {
            return "body{margin:0;padding:0;font-family:sans-serif}";
        }
        if (ext == ".json") {
            return "{\"status\":\"ok\",\"data\":{}}";
        }
        if (ext == ".xml") {
            return "<?xml version=\"1.0\"?><root><status>ok</status></root>";
        }
        if (ext == ".txt") {
            return "OK";
        }
        // Binary types: return small valid-looking stub
        if (ext == ".exe" || ext == ".dll") {
            return std::string("MZ") + std::string(62, '\0');
        }
        if (ext == ".pdf") {
            return "%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF";
        }
        if (ext == ".png") {
            // Minimal 1x1 transparent PNG
            static const uint8_t png[] = {
                0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,
                0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52,
                0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
                0x08,0x06,0x00,0x00,0x00,0x1F,0x15,0xC4,
                0x89,0x00,0x00,0x00,0x0A,0x49,0x44,0x41,
                0x54,0x78,0x9C,0x62,0x00,0x00,0x00,0x02,
                0x00,0x01,0xE5,0x27,0xDE,0xFC,0x00,0x00,
                0x00,0x00,0x49,0x45,0x4E,0x44,0xAE,0x42,
                0x60,0x82
            };
            return std::string((const char*)png, sizeof(png));
        }
        return "<html><body>OK</body></html>";
    }

    void handle_client(int client_fd) {
        char buf[4096];
        ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) { close(client_fd); return; }
        buf[n] = '\0';

        std::string request(buf, n);
        std::string path = extract_path(request);
        std::string ext = extract_extension(path);
        const char* mime = mime_for_ext(ext);
        std::string body = fake_body(ext);

        // Log the request (for analysis capture)
        // analysis_callback_(request, path, host);

        std::ostringstream resp;
        resp << "HTTP/1.1 200 OK\r\n"
             << "Content-Type: " << mime << "\r\n"
             << "Content-Length: " << body.size() << "\r\n"
             << "Connection: close\r\n"
             << "Server: Apache/2.4.41\r\n"
             << "\r\n"
             << body;

        std::string r = resp.str();
        send(client_fd, r.data(), r.size(), 0);
        close(client_fd);
    }

public:
    bool start(uint16_t port = 80) {
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;

        int reuse = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            return false;
        if (listen(listen_fd_, 128) < 0) return false;

        running_ = true;
        return true;
    }

    void run() {
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(listen_fd_,
                (struct sockaddr*)&client_addr, &addr_len);
            if (client_fd < 0) continue;
            std::thread(&fake_http_server::handle_client,
                        this, client_fd).detach();
        }
    }

    void stop() {
        running_ = false;
        if (listen_fd_ >= 0) { close(listen_fd_); listen_fd_ = -1; }
    }
};
```

### 4.3 TCP HTTPS Server — Auto-Generate TLS Cert per Hostname (BoringSSL)

```cpp
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <mutex>
#include <unordered_map>
#include <thread>

struct cert_entry {
    EVP_PKEY* key;
    X509* cert;
    SSL_CTX* ctx;
};

class fake_https_server {
    int listen_fd_ = -1;
    bool running_ = false;

    // CA key and cert (self-signed root)
    EVP_PKEY* ca_key_ = nullptr;
    X509* ca_cert_ = nullptr;

    // Per-hostname cert cache
    std::mutex cert_mutex_;
    std::unordered_map<std::string, cert_entry> cert_cache_;

    EVP_PKEY* generate_rsa_key(int bits = 2048) {
        EVP_PKEY* pkey = EVP_PKEY_new();
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);
        RSA* rsa = RSA_new();
        RSA_generate_key_ex(rsa, bits, bn, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);
        BN_free(bn);
        return pkey;
    }

    X509* generate_ca_cert(EVP_PKEY* key) {
        X509* cert = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600);
        X509_set_pubkey(cert, key);

        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char*)"ShieldTier Fake CA", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            (const unsigned char*)"ShieldTier Analysis", -1, -1, 0);

        X509_set_issuer_name(cert, name);

        // CA basic constraints
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(
            nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE");
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        X509_sign(cert, key, EVP_sha256());
        return cert;
    }

    cert_entry generate_host_cert(const std::string& hostname) {
        cert_entry entry;
        entry.key = generate_rsa_key(2048);

        X509* cert = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(cert), rand());
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 30 * 24 * 3600);
        X509_set_pubkey(cert, entry.key);

        // Subject CN = requested hostname
        X509_NAME* subj = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
            (const unsigned char*)hostname.c_str(), -1, -1, 0);

        // Issuer = our CA
        X509_set_issuer_name(cert, X509_get_subject_name(ca_cert_));

        // SAN extension for the hostname
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, ca_cert_, cert, nullptr, nullptr, 0);
        std::string san = "DNS:" + hostname;
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(
            nullptr, &ctx, NID_subject_alt_name, san.c_str());
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        // Sign with CA key
        X509_sign(cert, ca_key_, EVP_sha256());
        entry.cert = cert;

        // Create SSL_CTX for this hostname
        entry.ctx = SSL_CTX_new(TLS_server_method());
        SSL_CTX_use_certificate(entry.ctx, entry.cert);
        SSL_CTX_use_PrivateKey(entry.ctx, entry.key);

        return entry;
    }

    cert_entry& get_cert_for_host(const std::string& hostname) {
        std::lock_guard<std::mutex> lock(cert_mutex_);
        auto it = cert_cache_.find(hostname);
        if (it != cert_cache_.end()) return it->second;
        cert_cache_[hostname] = generate_host_cert(hostname);
        return cert_cache_[hostname];
    }

    // Extract SNI hostname from ClientHello via callback
    static int sni_callback(SSL* ssl, int* al, void* arg) {
        (void)al;
        fake_https_server* self = (fake_https_server*)arg;
        const char* servername = SSL_get_servername(ssl,
                                     TLSEXT_NAMETYPE_host_name);
        if (!servername) return SSL_TLSEXT_ERR_OK;

        auto& entry = self->get_cert_for_host(servername);
        SSL_set_SSL_CTX(ssl, entry.ctx);
        return SSL_TLSEXT_ERR_OK;
    }

    void handle_client(int client_fd) {
        // Default SSL_CTX (used before SNI callback fires)
        SSL_CTX* default_ctx = SSL_CTX_new(TLS_server_method());
        auto& default_cert = get_cert_for_host("localhost");
        SSL_CTX_use_certificate(default_ctx, default_cert.cert);
        SSL_CTX_use_PrivateKey(default_ctx, default_cert.key);
        SSL_CTX_set_tlsext_servername_callback(default_ctx, sni_callback);
        SSL_CTX_set_tlsext_servername_arg(default_ctx, this);

        SSL* ssl = SSL_new(default_ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(default_ctx);
            close(client_fd);
            return;
        }

        // Read HTTP request over TLS
        char buf[4096];
        int n = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            // Serve fake response (same logic as HTTP server)
            const char* body = "<html><body><h1>OK</h1></body></html>";
            char resp[1024];
            snprintf(resp, sizeof(resp),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n\r\n%s",
                strlen(body), body);
            SSL_write(ssl, resp, strlen(resp));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(default_ctx);
        close(client_fd);
    }

public:
    bool start(uint16_t port = 443) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();

        // Generate CA
        ca_key_ = generate_rsa_key(2048);
        ca_cert_ = generate_ca_cert(ca_key_);

        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        int reuse = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            return false;
        if (listen(listen_fd_, 128) < 0) return false;

        running_ = true;
        return true;
    }

    void run() {
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(listen_fd_,
                (struct sockaddr*)&client_addr, &addr_len);
            if (client_fd < 0) continue;
            std::thread(&fake_https_server::handle_client,
                        this, client_fd).detach();
        }
    }

    // Returns PEM-encoded CA cert for importing into guest trust store
    std::string get_ca_cert_pem() {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio, ca_cert_);
        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    void stop() {
        running_ = false;
        if (listen_fd_ >= 0) { close(listen_fd_); listen_fd_ = -1; }
    }
};
```

### 4.4 TCP SMTP Server

```cpp
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <sstream>

struct captured_email {
    std::string from;
    std::vector<std::string> to;
    std::string data;  // raw MIME body
    std::string subject;
};

class fake_smtp_server {
    int listen_fd_ = -1;
    bool running_ = false;
    std::vector<captured_email> captured_;
    std::mutex capture_mutex_;

    static void send_line(int fd, const char* line) {
        std::string s = std::string(line) + "\r\n";
        send(fd, s.data(), s.size(), 0);
    }

    static std::string recv_line(int fd) {
        std::string line;
        char c;
        while (recv(fd, &c, 1, 0) == 1) {
            if (c == '\n') {
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                return line;
            }
            line += c;
        }
        return line;
    }

    void handle_client(int client_fd) {
        send_line(client_fd, "220 mail.shieldtier.local ESMTP ready");

        captured_email email;
        bool in_data = false;
        std::string data_buf;

        while (true) {
            if (in_data) {
                std::string line = recv_line(client_fd);
                if (line == ".") {
                    in_data = false;
                    email.data = data_buf;
                    send_line(client_fd, "250 OK message queued");
                    std::lock_guard<std::mutex> lock(capture_mutex_);
                    captured_.push_back(std::move(email));
                    email = {};
                    data_buf.clear();
                } else {
                    data_buf += line + "\r\n";
                }
                continue;
            }

            std::string line = recv_line(client_fd);
            if (line.empty()) break;

            // Case-insensitive command prefix matching
            std::string upper;
            for (char c : line) upper += toupper(c);

            if (upper.substr(0, 4) == "EHLO" ||
                upper.substr(0, 4) == "HELO") {
                send_line(client_fd, "250-mail.shieldtier.local");
                send_line(client_fd, "250-SIZE 52428800");
                send_line(client_fd, "250-AUTH LOGIN PLAIN");
                send_line(client_fd, "250 OK");
            }
            else if (upper.substr(0, 4) == "AUTH") {
                // Accept any authentication
                send_line(client_fd, "235 Authentication successful");
            }
            else if (upper.substr(0, 9) == "MAIL FROM") {
                auto lt = line.find('<');
                auto gt = line.find('>');
                if (lt != std::string::npos && gt != std::string::npos)
                    email.from = line.substr(lt + 1, gt - lt - 1);
                send_line(client_fd, "250 OK");
            }
            else if (upper.substr(0, 7) == "RCPT TO") {
                auto lt = line.find('<');
                auto gt = line.find('>');
                if (lt != std::string::npos && gt != std::string::npos)
                    email.to.push_back(
                        line.substr(lt + 1, gt - lt - 1));
                send_line(client_fd, "250 OK");
            }
            else if (upper == "DATA") {
                in_data = true;
                send_line(client_fd,
                    "354 Start mail input; end with <CRLF>.<CRLF>");
            }
            else if (upper == "QUIT") {
                send_line(client_fd, "221 Bye");
                break;
            }
            else if (upper == "RSET") {
                email = {};
                send_line(client_fd, "250 OK");
            }
            else if (upper == "NOOP") {
                send_line(client_fd, "250 OK");
            }
            else {
                send_line(client_fd, "500 Command unrecognized");
            }
        }

        close(client_fd);
    }

public:
    bool start(uint16_t port = 25) {
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        int reuse = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            return false;
        if (listen(listen_fd_, 32) < 0) return false;
        running_ = true;
        return true;
    }

    void run() {
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(listen_fd_,
                (struct sockaddr*)&client_addr, &addr_len);
            if (client_fd < 0) continue;
            std::thread(&fake_smtp_server::handle_client,
                        this, client_fd).detach();
        }
    }

    const std::vector<captured_email>& get_captured() {
        return captured_;
    }

    void stop() {
        running_ = false;
        if (listen_fd_ >= 0) { close(listen_fd_); listen_fd_ = -1; }
    }
};
```

### 4.5 TCP FTP Server

```cpp
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>

struct captured_upload {
    std::string filename;
    std::vector<uint8_t> data;
    std::string username;
};

class fake_ftp_server {
    int listen_fd_ = -1;
    bool running_ = false;
    std::vector<captured_upload> uploads_;
    std::mutex upload_mutex_;

    static void send_reply(int fd, const char* msg) {
        std::string s = std::string(msg) + "\r\n";
        send(fd, s.data(), s.size(), 0);
    }

    static std::string recv_line(int fd) {
        std::string line;
        char c;
        while (recv(fd, &c, 1, 0) == 1) {
            if (c == '\n') {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                return line;
            }
            line += c;
        }
        return line;
    }

    void handle_client(int client_fd) {
        send_reply(client_fd, "220 FTP server ready");

        std::string username;
        std::string current_filename;
        int data_listen_fd = -1;

        while (true) {
            std::string line = recv_line(client_fd);
            if (line.empty()) break;

            std::string cmd, arg;
            auto sp = line.find(' ');
            if (sp != std::string::npos) {
                cmd = line.substr(0, sp);
                arg = line.substr(sp + 1);
            } else {
                cmd = line;
            }
            for (char& c : cmd) c = toupper(c);

            if (cmd == "USER") {
                username = arg;
                send_reply(client_fd, "331 Password required");
            }
            else if (cmd == "PASS") {
                // Accept any password
                send_reply(client_fd, "230 Login successful");
            }
            else if (cmd == "SYST") {
                send_reply(client_fd, "215 UNIX Type: L8");
            }
            else if (cmd == "PWD") {
                send_reply(client_fd, "257 \"/\" is current directory");
            }
            else if (cmd == "TYPE") {
                send_reply(client_fd, "200 Type set");
            }
            else if (cmd == "PASV") {
                // Open passive data port
                data_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in daddr = {};
                daddr.sin_family = AF_INET;
                daddr.sin_addr.s_addr = INADDR_ANY;
                daddr.sin_port = 0;  // kernel picks port
                bind(data_listen_fd, (struct sockaddr*)&daddr,
                     sizeof(daddr));
                listen(data_listen_fd, 1);

                socklen_t len = sizeof(daddr);
                getsockname(data_listen_fd,
                    (struct sockaddr*)&daddr, &len);
                uint16_t port = ntohs(daddr.sin_port);

                char reply[128];
                snprintf(reply, sizeof(reply),
                    "227 Entering Passive Mode (127,0,0,1,%d,%d)",
                    port / 256, port % 256);
                send_reply(client_fd, reply);
            }
            else if (cmd == "STOR") {
                current_filename = arg;
                send_reply(client_fd,
                    "150 Opening data connection");

                if (data_listen_fd >= 0) {
                    struct sockaddr_in da;
                    socklen_t dl = sizeof(da);
                    int data_fd = accept(data_listen_fd,
                        (struct sockaddr*)&da, &dl);

                    // Read upload into memory
                    std::vector<uint8_t> file_data;
                    uint8_t buf[8192];
                    ssize_t n;
                    while ((n = recv(data_fd, buf, sizeof(buf), 0)) > 0) {
                        file_data.insert(file_data.end(), buf, buf + n);
                    }
                    close(data_fd);
                    close(data_listen_fd);
                    data_listen_fd = -1;

                    {
                        std::lock_guard<std::mutex> lock(upload_mutex_);
                        uploads_.push_back({
                            current_filename,
                            std::move(file_data),
                            username
                        });
                    }

                    send_reply(client_fd, "226 Transfer complete");
                }
            }
            else if (cmd == "QUIT") {
                send_reply(client_fd, "221 Goodbye");
                break;
            }
            else {
                send_reply(client_fd, "502 Command not implemented");
            }
        }

        if (data_listen_fd >= 0) close(data_listen_fd);
        close(client_fd);
    }

public:
    bool start(uint16_t port = 21) {
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        int reuse = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            return false;
        if (listen(listen_fd_, 32) < 0) return false;
        running_ = true;
        return true;
    }

    void run() {
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(listen_fd_,
                (struct sockaddr*)&client_addr, &addr_len);
            if (client_fd < 0) continue;
            std::thread(&fake_ftp_server::handle_client,
                        this, client_fd).detach();
        }
    }

    const std::vector<captured_upload>& get_uploads() { return uploads_; }

    void stop() {
        running_ = false;
        if (listen_fd_ >= 0) { close(listen_fd_); listen_fd_ = -1; }
    }
};
```

---

## 5. QEMU Orchestration (C++)

### 5.1 Building QEMU Command-Line Arguments

```cpp
#include <string>
#include <vector>
#include <sstream>

struct qemu_config {
    std::string qemu_binary = "qemu-system-x86_64";
    std::string machine = "q35";
    std::string cpu = "host,kvm=off";  // kvm=off hides hypervisor
    int memory_mb = 4096;
    int smp = 2;
    std::string disk_image;             // qcow2 path
    std::string snapshot_name;          // for loadvm
    std::string qmp_socket;            // QMP unix socket path
    std::string virtio_socket;         // virtio-serial socket path
    std::string tap_ifname = "vmtap0"; // TAP interface for netsim
    bool enable_kvm = true;
    bool snapshot_mode = true;         // -snapshot (discard disk writes)
};

std::vector<std::string> build_qemu_args(const qemu_config& cfg) {
    std::vector<std::string> args;
    args.push_back(cfg.qemu_binary);

    // Machine
    args.push_back("-machine");
    args.push_back(cfg.machine + ",accel=" +
                   (cfg.enable_kvm ? "kvm" : "tcg"));

    // CPU — hide hypervisor from guest
    args.push_back("-cpu");
    args.push_back(cfg.cpu);

    // Memory
    args.push_back("-m");
    args.push_back(std::to_string(cfg.memory_mb));

    // SMP
    args.push_back("-smp");
    args.push_back(std::to_string(cfg.smp));

    // Disk
    args.push_back("-drive");
    args.push_back("file=" + cfg.disk_image +
                   ",format=qcow2,if=virtio,cache=writeback");

    if (cfg.snapshot_mode) {
        args.push_back("-snapshot");
    }

    // Network — TAP backend for routing to INetSim
    args.push_back("-netdev");
    args.push_back("tap,id=net0,ifname=" + cfg.tap_ifname +
                   ",script=no,downscript=no");
    args.push_back("-device");
    args.push_back("virtio-net-pci,netdev=net0,"
                   "mac=52:54:00:12:34:56");

    // QMP socket for VM control
    args.push_back("-qmp");
    args.push_back("unix:" + cfg.qmp_socket + ",server,nowait");

    // Virtio-serial for guest agent communication
    args.push_back("-device");
    args.push_back("virtio-serial");
    args.push_back("-chardev");
    args.push_back("socket,path=" + cfg.virtio_socket +
                   ",server=on,wait=off,id=agent0");
    args.push_back("-device");
    args.push_back("virtserialport,chardev=agent0,"
                   "name=com.shieldtier.agent");

    // Display off for headless sandbox
    args.push_back("-display");
    args.push_back("none");

    // Load snapshot if specified
    if (!cfg.snapshot_name.empty()) {
        args.push_back("-loadvm");
        args.push_back(cfg.snapshot_name);
    }

    return args;
}
```

### 5.2 QMP Client (QEMU Machine Protocol)

```cpp
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string>
#include <stdexcept>

// Uses nlohmann/json or any JSON library.
// Shown here with raw strings for clarity.

class qmp_client {
    int fd_ = -1;

    std::string read_response() {
        std::string result;
        char buf[4096];
        // QMP sends newline-terminated JSON
        while (true) {
            ssize_t n = recv(fd_, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            buf[n] = '\0';
            result += buf;
            if (result.find('\n') != std::string::npos) break;
        }
        return result;
    }

    std::string send_command(const std::string& json_cmd) {
        std::string msg = json_cmd + "\r\n";
        send(fd_, msg.data(), msg.size(), 0);
        return read_response();
    }

public:
    bool connect(const std::string& socket_path) {
        fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd_ < 0) return false;

        struct sockaddr_un addr = {};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path.c_str(),
                sizeof(addr.sun_path) - 1);

        if (::connect(fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd_);
            fd_ = -1;
            return false;
        }

        // Read greeting
        std::string greeting = read_response();
        // greeting contains: {"QMP": {"version": {...}, "capabilities": [...]}}

        // Negotiate capabilities (required before any command)
        send_command("{\"execute\": \"qmp_capabilities\"}");
        // Response: {"return": {}}

        return true;
    }

    std::string query_status() {
        return send_command("{\"execute\": \"query-status\"}");
        // {"return": {"status": "running", "singlestep": false, "running": true}}
    }

    std::string save_snapshot(const std::string& name) {
        // savevm is a HMP command; use human-monitor-command to invoke via QMP
        return send_command(
            "{\"execute\": \"human-monitor-command\","
            " \"arguments\": {\"command-line\": \"savevm " + name + "\"}}");
    }

    std::string load_snapshot(const std::string& name) {
        return send_command(
            "{\"execute\": \"human-monitor-command\","
            " \"arguments\": {\"command-line\": \"loadvm " + name + "\"}}");
    }

    std::string pause_vm() {
        return send_command("{\"execute\": \"stop\"}");
    }

    std::string resume_vm() {
        return send_command("{\"execute\": \"cont\"}");
    }

    std::string powerdown() {
        return send_command("{\"execute\": \"system_powerdown\"}");
    }

    std::string reset() {
        return send_command("{\"execute\": \"system_reset\"}");
    }

    std::string screendump(const std::string& path) {
        return send_command(
            "{\"execute\": \"screendump\","
            " \"arguments\": {\"filename\": \"" + path + "\"}}");
    }

    void disconnect() {
        if (fd_ >= 0) { close(fd_); fd_ = -1; }
    }

    ~qmp_client() { disconnect(); }
};
```

### 5.3 Virtio-Serial Agent Communication (NDJSON Protocol)

```cpp
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string>
#include <functional>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>

// NDJSON = newline-delimited JSON, one message per line.
// Host side connects to the virtio-serial UNIX socket.
// Guest side reads/writes /dev/virtio-ports/com.shieldtier.agent

// Message types (host <-> guest):
//   {"type":"exec","id":"abc","cmd":"notepad.exe","args":["file.txt"]}
//   {"type":"exec_result","id":"abc","pid":1234,"exit_code":0,"stdout":"..."}
//   {"type":"file_write","path":"C:\\temp\\sample.exe","data":"<base64>"}
//   {"type":"file_read","path":"C:\\temp\\output.txt"}
//   {"type":"proc_list"}
//   {"type":"screenshot"}
//   {"type":"heartbeat"}

class virtio_agent_client {
    int fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread reader_thread_;
    std::mutex write_mutex_;

    using message_callback = std::function<void(const std::string&)>;
    message_callback on_message_;

    void reader_loop() {
        std::string buffer;
        char chunk[4096];

        while (running_) {
            ssize_t n = recv(fd_, chunk, sizeof(chunk), 0);
            if (n <= 0) {
                if (running_) {
                    // Connection lost, attempt reconnect
                }
                break;
            }

            buffer.append(chunk, n);

            // Process complete lines (NDJSON)
            size_t pos;
            while ((pos = buffer.find('\n')) != std::string::npos) {
                std::string line = buffer.substr(0, pos);
                buffer.erase(0, pos + 1);

                if (!line.empty() && on_message_) {
                    on_message_(line);
                }
            }
        }
    }

public:
    bool connect(const std::string& socket_path,
                 message_callback cb) {
        on_message_ = cb;

        fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd_ < 0) return false;

        struct sockaddr_un addr = {};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path.c_str(),
                sizeof(addr.sun_path) - 1);

        if (::connect(fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd_);
            fd_ = -1;
            return false;
        }

        running_ = true;
        reader_thread_ = std::thread(&virtio_agent_client::reader_loop,
                                      this);
        return true;
    }

    bool send_message(const std::string& json_line) {
        std::lock_guard<std::mutex> lock(write_mutex_);
        std::string msg = json_line + "\n";
        ssize_t sent = ::send(fd_, msg.data(), msg.size(), 0);
        return sent == (ssize_t)msg.size();
    }

    // Convenience methods
    bool execute(const std::string& id, const std::string& cmd) {
        return send_message(
            "{\"type\":\"exec\",\"id\":\"" + id +
            "\",\"cmd\":\"" + cmd + "\"}");
    }

    bool request_screenshot(const std::string& id) {
        return send_message(
            "{\"type\":\"screenshot\",\"id\":\"" + id + "\"}");
    }

    bool heartbeat() {
        return send_message("{\"type\":\"heartbeat\"}");
    }

    void disconnect() {
        running_ = false;
        if (fd_ >= 0) {
            shutdown(fd_, SHUT_RDWR);
            close(fd_);
            fd_ = -1;
        }
        if (reader_thread_.joinable()) reader_thread_.join();
    }

    ~virtio_agent_client() { disconnect(); }
};
```

---

## 6. proc_connector (Linux Guest Agent)

### 6.1 Process Monitoring via Netlink

```cpp
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>

static volatile sig_atomic_t running = 1;

static void sighandler(int sig) {
    (void)sig;
    running = 0;
}

// Subscribe to proc events
static int proc_connector_subscribe(int nl_sock) {
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__((packed)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } msg = {};

    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_pid = getpid();
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    msg.cn_msg.id.idx = CN_IDX_PROC;
    msg.cn_msg.id.val = CN_VAL_PROC;
    msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    msg.cn_mcast = PROC_CN_MCAST_LISTEN;

    if (send(nl_sock, &msg, sizeof(msg), 0) == -1) {
        return -1;
    }
    return 0;
}

// Read and print /proc/<pid>/cmdline
static void print_cmdline(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE* f = fopen(path, "r");
    if (!f) return;
    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    // cmdline uses \0 as separator
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    buf[n] = '\0';
    printf("  cmdline: %s\n", buf);
}

int main() {
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    // Step 1: Create netlink socket
    int nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock < 0) {
        perror("socket(NETLINK_CONNECTOR)");
        return 1;
    }

    // Step 2: Bind
    struct sockaddr_nl sa_nl = {};
    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();

    if (bind(nl_sock, (struct sockaddr*)&sa_nl, sizeof(sa_nl)) < 0) {
        perror("bind");
        close(nl_sock);
        return 1;
    }

    // Step 3: Subscribe to proc events
    if (proc_connector_subscribe(nl_sock) < 0) {
        perror("subscribe");
        close(nl_sock);
        return 1;
    }

    printf("Listening for process events (Ctrl+C to stop)...\n");

    // Step 4: Receive events
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__((packed)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } recv_msg;

    while (running) {
        ssize_t len = recv(nl_sock, &recv_msg, sizeof(recv_msg), 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Verify this is from proc connector
        if (recv_msg.cn_msg.id.idx != CN_IDX_PROC ||
            recv_msg.cn_msg.id.val != CN_VAL_PROC) {
            continue;
        }

        struct proc_event* ev = &recv_msg.proc_ev;

        switch (ev->what) {
        case PROC_EVENT_FORK:
            printf("FORK: parent_pid=%d parent_tgid=%d "
                   "child_pid=%d child_tgid=%d\n",
                   ev->event_data.fork.parent_pid,
                   ev->event_data.fork.parent_tgid,
                   ev->event_data.fork.child_pid,
                   ev->event_data.fork.child_tgid);
            break;

        case PROC_EVENT_EXEC:
            printf("EXEC: pid=%d tgid=%d\n",
                   ev->event_data.exec.process_pid,
                   ev->event_data.exec.process_tgid);
            print_cmdline(ev->event_data.exec.process_pid);
            break;

        case PROC_EVENT_EXIT:
            printf("EXIT: pid=%d tgid=%d exit_code=%d\n",
                   ev->event_data.exit.process_pid,
                   ev->event_data.exit.process_tgid,
                   ev->event_data.exit.exit_code);
            break;

        case PROC_EVENT_UID:
            printf("UID:  pid=%d ruid=%d euid=%d\n",
                   ev->event_data.id.process_pid,
                   ev->event_data.id.r.ruid,
                   ev->event_data.id.e.euid);
            break;

        case PROC_EVENT_GID:
            printf("GID:  pid=%d rgid=%d egid=%d\n",
                   ev->event_data.id.process_pid,
                   ev->event_data.id.r.rgid,
                   ev->event_data.id.e.egid);
            break;

        case PROC_EVENT_SID:
            printf("SID:  pid=%d\n",
                   ev->event_data.sid.process_pid);
            break;

        default:
            break;
        }
    }

    // Unsubscribe (optional)
    close(nl_sock);
    return 0;
}
```

Requires `CAP_NET_ADMIN` capability or root. Compile with:

```bash
gcc -o proc_monitor proc_monitor.c -Wall -Wextra
sudo ./proc_monitor
```

---

## 7. Cross-Platform Hypervisor Abstraction

For ShieldTier's `src/native/vm/`, a unified interface wrapping all three:

```cpp
// src/native/vm/hypervisor.h

#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>

enum class hv_backend { apple_hv, linux_kvm, windows_whpx };

struct vcpu_registers {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
    uint64_t cr0, cr3, cr4;
};

enum class vmexit_reason {
    io_out,
    io_in,
    mmio_read,
    mmio_write,
    halt,
    cpuid,
    ept_violation,
    shutdown,
    unknown,
};

struct vmexit_info {
    vmexit_reason reason;
    uint16_t io_port;
    uint8_t io_size;
    uint64_t io_data;
    uint64_t gpa;           // for EPT/MMIO
    uint64_t insn_length;
};

using dirty_page_callback = std::function<void(uint64_t gpa)>;

class hypervisor {
public:
    virtual ~hypervisor() = default;

    virtual bool create_vm() = 0;
    virtual bool map_memory(void* host_addr, uint64_t guest_phys,
                            size_t size, bool read, bool write,
                            bool exec) = 0;
    virtual bool unmap_memory(uint64_t guest_phys, size_t size) = 0;
    virtual bool create_vcpu(int vcpu_id) = 0;

    virtual bool get_registers(int vcpu_id, vcpu_registers& regs) = 0;
    virtual bool set_registers(int vcpu_id,
                               const vcpu_registers& regs) = 0;

    virtual vmexit_info run(int vcpu_id) = 0;

    // Dirty page tracking
    virtual bool enable_dirty_tracking(int slot) = 0;
    virtual bool get_dirty_pages(int slot,
                                 dirty_page_callback cb) = 0;

    // CPUID masking
    virtual bool hide_hypervisor() = 0;

    virtual void destroy() = 0;

    static hypervisor* create(hv_backend backend);
};
```

---

## Sources

- [Apple Hypervisor.framework Documentation](https://developer.apple.com/documentation/hypervisor)
- [pagetable.com — Hypervisor Framework DOS Emulator](https://www.pagetable.com/?p=764)
- [hypervisor-framework-ex on GitHub](https://github.com/fntlnz/hypervisor-framework-ex/blob/master/hypervisor.c)
- [xhyve — Lightweight macOS Virtualization](https://github.com/machyve/xhyve)
- [KVM Host in a Few Lines of Code (zserge.com)](https://zserge.com/posts/kvm/)
- [Linux KVM API Documentation](https://www.kernel.org/doc/html/v6.0/virt/kvm/api.html)
- [Using the KVM API (LWN.net)](https://lwn.net/Articles/658511/)
- [Building a Hypervisor with KVM](https://iovec.net/2024-01-29)
- [WHP-simple on GitHub](https://github.com/utshina/WHP-simple)
- [WHvCreatePartition — Microsoft Learn](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatepartition)
- [WHvQueryGpaRangeDirtyBitmap — Microsoft Learn](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvquerygparangedirtybitmap)
- [QEMU QMP Specification](https://www.qemu.org/docs/master/interop/qmp-spec.html)
- [QEMU QMP Reference Manual](https://qemu-project.gitlab.io/qemu/interop/qemu-qmp-ref.html)
- [QEMU Snapshot Deep Dive (Airbus SecLab)](https://airbus-seclab.github.io/qemu_blog/snapshot.html)
- [Virtio-Serial API (linux-kvm.org)](https://www.linux-kvm.org/page/Virtio-serial_API)
- [QEMU Guest Agent virtio-serial setup](https://virtio-win.github.io/Knowledge-Base/Qemu-ga-win.html)
- [proc_connector — Process Events Connector (LWN.net)](https://lwn.net/Articles/157150/)
- [Linux Process Monitoring with Netlink (bewareofgeek)](https://bewareofgeek.livejournal.com/2945.html)
- [Proc Connector and Socket Filters (dankwiki)](https://nick-black.com/dankwiki/index.php/The_Proc_Connector_and_Socket_Filters)
- [KVM-VMI — Virtual Machine Introspection](https://github.com/KVM-VMI/kvm-vmi)
- [DdiMon — EPT Hook Monitoring](https://github.com/tandasat/DdiMon)
- [QEMU Anti-Detection Techniques (DeepWiki)](https://deepwiki.com/dsecuma/qemu-anti-detection/3-anti-detection-techniques)
- [Hypervisor Concealment — CPUID Masking](https://deepwiki.com/dsecuma/qemu-anti-detection/3.3-hypervisor-concealment)
- [KVM CPUID Documentation](https://docs.kernel.org/virt/kvm/x86/cpuid.html)
- [INetSim — Internet Services Simulation Suite](https://www.inetsim.org/features.html)
- [DNS Tunneling Detection (CyberDefenders)](https://cyberdefenders.org/blog/dns-tunneling-detection/)
- [Understanding DNS Tunneling Traffic (Unit42)](https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild/)
- [BoringSSL x509 header](https://boringssl.googlesource.com/boringssl/+/refs/heads/master/include/openssl/x509.h)
- [OpenSSL Self-Signed Certificate Example](https://gist.github.com/nathan-osman/5041136)
