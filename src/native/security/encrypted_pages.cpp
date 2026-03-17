#include "security/encrypted_pages.h"

#include <cstring>

#if defined(__APPLE__) || defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace shieldtier {

namespace {

// Align an address down to page boundary
uintptr_t page_align_down(uintptr_t addr) {
#if defined(__APPLE__) || defined(__linux__)
    long page_size = sysconf(_SC_PAGESIZE);
#elif defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    long page_size = si.dwPageSize;
#else
    long page_size = 4096;
#endif
    return addr & ~(static_cast<uintptr_t>(page_size) - 1);
}

size_t page_align_length(uintptr_t addr, size_t length) {
#if defined(__APPLE__) || defined(__linux__)
    long page_size = sysconf(_SC_PAGESIZE);
#elif defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    long page_size = si.dwPageSize;
#else
    long page_size = 4096;
#endif
    uintptr_t start = page_align_down(addr);
    uintptr_t end = (addr + length + page_size - 1) & ~(static_cast<uintptr_t>(page_size) - 1);
    return static_cast<size_t>(end - start);
}

}  // namespace

void EncryptedPages::xor_region(void* addr, size_t length, uint64_t key) {
    auto* bytes = static_cast<uint8_t*>(addr);
    auto* key_bytes = reinterpret_cast<const uint8_t*>(&key);

    // Expand key across the region using repeating XOR of the 8-byte key
    // with a position-dependent twist to avoid simple repeating patterns
    for (size_t i = 0; i < length; ++i) {
        uint8_t stream_byte = key_bytes[i % 8];
        // Mix in position to create a pseudo-random stream
        stream_byte ^= static_cast<uint8_t>((i * 0x9E3779B97F4A7C15ULL) >> 56);
        bytes[i] ^= stream_byte;
    }
}

bool EncryptedPages::set_page_writable(void* addr, size_t length) {
#if defined(__APPLE__) || defined(__linux__)
    uintptr_t aligned = page_align_down(reinterpret_cast<uintptr_t>(addr));
    size_t aligned_len = page_align_length(reinterpret_cast<uintptr_t>(addr), length);
    return mprotect(reinterpret_cast<void*>(aligned), aligned_len,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
#elif defined(_WIN32)
    DWORD old_protect;
    return VirtualProtect(addr, length, PAGE_EXECUTE_READWRITE, &old_protect) != 0;
#else
    return false;
#endif
}

bool EncryptedPages::restore_page_protection(void* addr, size_t length) {
#if defined(__APPLE__) || defined(__linux__)
    uintptr_t aligned = page_align_down(reinterpret_cast<uintptr_t>(addr));
    size_t aligned_len = page_align_length(reinterpret_cast<uintptr_t>(addr), length);
    return mprotect(reinterpret_cast<void*>(aligned), aligned_len,
                    PROT_READ | PROT_EXEC) == 0;
#elif defined(_WIN32)
    DWORD old_protect;
    return VirtualProtect(addr, length, PAGE_EXECUTE_READ, &old_protect) != 0;
#else
    return false;
#endif
}

void EncryptedPages::encrypt_page(void* addr, size_t length, uint64_t key) {
    std::lock_guard lock(mutex_);

    uintptr_t key_addr = reinterpret_cast<uintptr_t>(addr);

    if (!set_page_writable(addr, length)) return;
    xor_region(addr, length, key);
    restore_page_protection(addr, length);

    pages_[key_addr] = {addr, length, key, false};
}

void EncryptedPages::decrypt_page(void* addr, size_t length, uint64_t key) {
    std::lock_guard lock(mutex_);

    uintptr_t key_addr = reinterpret_cast<uintptr_t>(addr);

    auto it = pages_.find(key_addr);
    if (it != pages_.end() && it->second.decrypted) return;

    if (!set_page_writable(addr, length)) return;
    xor_region(addr, length, key);
    restore_page_protection(addr, length);

    if (it != pages_.end()) {
        it->second.decrypted = true;
    } else {
        pages_[key_addr] = {addr, length, key, true};
    }
}

void EncryptedPages::reencrypt_page(void* addr) {
    std::lock_guard lock(mutex_);

    uintptr_t key_addr = reinterpret_cast<uintptr_t>(addr);
    auto it = pages_.find(key_addr);
    if (it == pages_.end() || !it->second.decrypted) return;

    auto& info = it->second;
    if (!set_page_writable(info.addr, info.length)) return;
    xor_region(info.addr, info.length, info.key);
    restore_page_protection(info.addr, info.length);

    info.decrypted = false;
}

bool EncryptedPages::is_decrypted(void* addr) const {
    std::lock_guard lock(mutex_);
    uintptr_t key_addr = reinterpret_cast<uintptr_t>(addr);
    auto it = pages_.find(key_addr);
    if (it == pages_.end()) return false;
    return it->second.decrypted;
}

}  // namespace shieldtier
