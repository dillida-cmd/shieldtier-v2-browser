#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace shieldtier {

struct CodeRegion {
    const void* start;
    size_t length;
    uint64_t expected_hash;
};

class IntegrityGuard {
public:
    void register_region(const void* start, size_t length);
    void seal();
    bool verify_all() const;

    void set_corruption_callback(std::function<void()> cb);
    void check_and_respond();

private:
    uint64_t compute_hash(const void* data, size_t len) const;

    std::vector<CodeRegion> regions_;
    bool sealed_ = false;
    std::function<void()> corruption_callback_;
};

}  // namespace shieldtier
