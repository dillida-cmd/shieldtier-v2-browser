#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace shieldtier {

class EncryptedPages {
public:
    void encrypt_page(void* addr, size_t length, uint64_t key);
    void decrypt_page(void* addr, size_t length, uint64_t key);
    void reencrypt_page(void* addr);
    bool is_decrypted(void* addr) const;

private:
    struct PageInfo {
        void* addr;
        size_t length;
        uint64_t key;
        bool decrypted;
    };

    void xor_region(void* addr, size_t length, uint64_t key);
    bool set_page_writable(void* addr, size_t length);
    bool restore_page_protection(void* addr, size_t length);

    std::unordered_map<uintptr_t, PageInfo> pages_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
