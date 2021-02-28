#include "net/shadowsocks/hash-filter.h"

#include <algorithm>

namespace net {
namespace shadowsocks {

HashFilter::HashFilter()
    : buckets_(std::make_unique<Bucket[]>(num_buckets_)) {}

void HashFilter::clear() {
    std::fill(&buckets_[0], &buckets_[num_buckets_], Bucket());
    size_ = 0;
}

bool HashFilter::insert(uint64_t fingerprint) {
    uint32_t index = (fingerprint >> 32) & (num_buckets_ - 1);
    uint32_t fp32 = fingerprint;
    if (add(fp32, buckets_[index])) {
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
    uint32_t index = (fingerprint >> 32) & (num_buckets_ - 1);
    uint32_t fp32 = fingerprint;
    if (find(buckets_[index], fp32)) {
        return true;
    }
    index ^= fp32 & (num_buckets_ - 1);
    return find(buckets_[index], fp32);
}

bool HashFilter::add(uint32_t fp32, Bucket &bucket) {
    for (uint32_t &entry : bucket.entries) {
        if (!entry) {
            entry = fp32;
            return true;
        }
    }
    return false;
}

bool HashFilter::find(const Bucket &bucket, uint32_t fp32) {
    for (uint32_t entry : bucket.entries) {
        if (!entry) {
            return false;
        }
        if (entry == fp32) {
            return true;
        }
    }
    return false;
}

}  // namespace shadowsocks
}  // namespace net
