#include "net/proxy/shadowsocks/salt-filter.h"

#include <openssl/rand.h>
#include <openssl/siphash.h>

namespace net {
namespace proxy {
namespace shadowsocks {

SaltFilter::SaltFilter()
    : filter0_(262144),
      filter1_(262144) {
    RAND_bytes(reinterpret_cast<uint8_t *>(key_.data()), sizeof(key_));
}

bool SaltFilter::test_and_insert(ConstBufferSpan salt) {
    uint64_t fingerprint = SIPHASH_24(key_.data(), salt.data(), salt.size());
    if (filter0_.test(fingerprint) || filter1_.test(fingerprint)) {
        return false;
    }
    insert(fingerprint);
    return true;
}

void SaltFilter::insert(ConstBufferSpan salt) {
    insert(SIPHASH_24(key_.data(), salt.data(), salt.size()));
}

void SaltFilter::insert(uint64_t fingerprint) {
    if (filter0_.size() >= 800000) {
        using std::swap;
        swap(filter0_, filter1_);
        filter0_.clear();
    }
    filter0_.insert(fingerprint);
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
