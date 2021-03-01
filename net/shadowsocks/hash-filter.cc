#include "net/shadowsocks/hash-filter.h"

#ifdef __SSE2__
#include <emmintrin.h>
#endif
#include <algorithm>
#include <cstring>

#include "absl/base/optimization.h"

namespace net {
namespace shadowsocks {

HashFilter::HashFilter()
    : buckets_(std::make_unique<Bucket[]>(num_buckets_)) {
    clear();
}

void HashFilter::clear() {
    memset(buckets_.get(), 0, num_buckets_ * sizeof(Bucket));
    size_ = 0;
}

bool HashFilter::insert(uint64_t fingerprint) {
    uint32_t fp32 = fingerprint;
    if (ABSL_PREDICT_FALSE(!fp32)) {
        fp32 = (fingerprint >> 32) | 1;
    }
    uint32_t index = (fingerprint >> 32) & (num_buckets_ - 1);
    if (ABSL_PREDICT_TRUE(add(fp32, buckets_[index]))) {
        ++size_;
        return true;
    }
    index ^= fp32 & (num_buckets_ - 1);
    if (add(fp32, buckets_[index])) {
        ++size_;
        return true;
    }
    for (int i = 0; i < 16; ++i) {
        uint64_t seed = absl::Uniform<uint64_t>(gen_);
        for (int j = 0; j < 32; ++j) {
            uint32_t &entry = buckets_[index].entries[seed & 3];
            seed >>= 2;
            std::swap(fp32, entry);
            index ^= fp32 & (num_buckets_ - 1);
            if (add(fp32, buckets_[index])) {
                ++size_;
                return true;
            }
        }
    }
    return false;
}

bool HashFilter::test(uint64_t fingerprint) const {
    uint32_t fp32 = fingerprint;
    if (ABSL_PREDICT_FALSE(!fp32)) {
        fp32 = (fingerprint >> 32) | 1;
    }
    uint32_t index = (fingerprint >> 32) & (num_buckets_ - 1);
    return find_two(
        buckets_[index],
        buckets_[index ^ (fp32 & (num_buckets_ - 1))],
        fp32);
}

bool HashFilter::add(uint32_t fp32, Bucket &bucket) {
    for (uint32_t &entry : bucket.entries) {
        if (ABSL_PREDICT_TRUE(!entry)) {
            entry = fp32;
            return true;
        }
    }
    return false;
}

bool HashFilter::find_two(const Bucket &b0, const Bucket &b1, uint32_t fp32) {
#ifdef __SSE2__
    __m128i a0 = _mm_loadu_si128(
        reinterpret_cast<const __m128i *>(b0.entries.data()));
    __m128i a1 = _mm_loadu_si128(
        reinterpret_cast<const __m128i *>(b1.entries.data()));
    __m128i b = _mm_set1_epi32(fp32);
    __m128i c0 = _mm_cmpeq_epi32(a0, b);
    __m128i c1 = _mm_cmpeq_epi32(a1, b);
    return _mm_movemask_epi8(_mm_or_si128(c0, c1));
#else
    for (uint32_t entry : b0.entries) {
        if (entry == fp32) {
            return true;
        }
    }
    for (uint32_t entry : b1.entries) {
        if (entry == fp32) {
            return true;
        }
    }
    return false;
#endif
}

}  // namespace shadowsocks
}  // namespace net
