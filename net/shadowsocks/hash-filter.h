#ifndef _NET_SHADOWSOCKS_HASH_FILTER_H
#define _NET_SHADOWSOCKS_HASH_FILTER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>

#include "absl/random/random.h"

namespace net {
namespace shadowsocks {

// Hash filter for replay attack prevention with 32-bit per entry.
//
// The implementation follows the article:
//
// Cuckoo Filter: Practically Better Than Bloom
// http://www.cs.cmu.edu/~binfan/papers/conext14_cuckoofilter.pdf
class HashFilter {
public:
    HashFilter();

    void clear();
    bool insert(uint64_t fingerprint);
    bool test(uint64_t fingerprint) const;

    size_t size() const { return size_; }

private:
    struct Bucket {
        std::array<uint32_t, 4> entries;
    };
    static_assert(std::is_trivial_v<Bucket>);

    static bool add(uint32_t fp32, Bucket &bucket);
    static bool find(const Bucket &bucket, uint32_t fp32);

    std::unique_ptr<Bucket[]> buckets_;
    static constexpr size_t num_buckets_ = 262144;
    size_t size_;
    absl::InsecureBitGen gen_;
};

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_HASH_FILTER_H
