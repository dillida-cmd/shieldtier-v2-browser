#include "security/integrity_guard.h"

#include <cstring>

namespace shieldtier {

namespace {

// FNV-1a 64-bit — fast, no external dependencies
constexpr uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

uint64_t fnv1a_64(const void* data, size_t len) {
    auto* bytes = static_cast<const uint8_t*>(data);
    uint64_t hash = kFnvOffsetBasis;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(bytes[i]);
        hash *= kFnvPrime;
    }
    return hash;
}

}  // namespace

uint64_t IntegrityGuard::compute_hash(const void* data, size_t len) const {
    return fnv1a_64(data, len);
}

void IntegrityGuard::register_region(const void* start, size_t length) {
    if (sealed_) return;
    regions_.push_back({start, length, 0});
}

void IntegrityGuard::seal() {
    if (sealed_) return;
    for (auto& region : regions_) {
        region.expected_hash = compute_hash(region.start, region.length);
    }
    sealed_ = true;
}

bool IntegrityGuard::verify_all() const {
    if (!sealed_) return true;
    for (const auto& region : regions_) {
        uint64_t current = compute_hash(region.start, region.length);
        if (current != region.expected_hash) {
            return false;
        }
    }
    return true;
}

void IntegrityGuard::set_corruption_callback(std::function<void()> cb) {
    corruption_callback_ = std::move(cb);
}

void IntegrityGuard::check_and_respond() {
    // Never throw, never crash. Silent corruption only.
    if (!sealed_) return;
    if (verify_all()) return;

    if (corruption_callback_) {
        try {
            corruption_callback_();
        } catch (...) {
            // Swallow all exceptions — silent corruption, never crash
        }
    }
}

}  // namespace shieldtier
