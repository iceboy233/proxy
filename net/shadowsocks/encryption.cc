#include "net/shadowsocks/encryption.h"

#include <openssl/siphash.h>
#include <cstdlib>

namespace net {
namespace shadowsocks {

SaltFilter::SaltFilter()
    : filter0_(262144),
      filter1_(262144) {
    RAND_bytes(reinterpret_cast<uint8_t *>(key_.data()), sizeof(key_));
}

bool SaltFilter::test_and_insert(absl::Span<const uint8_t> salt) {
    uint64_t fingerprint = SIPHASH_24(key_.data(), salt.data(), salt.size());
    if (filter0_.test(fingerprint) || filter1_.test(fingerprint)) {
        return false;
    }
    insert(fingerprint);
    return true;
}

void SaltFilter::insert(absl::Span<const uint8_t> salt) {
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

EncryptedStream::EncryptedStream(
    tcp::socket &socket,
    const proxy::shadowsocks::PreSharedKey &pre_shared_key,
    SaltFilter *salt_filter)
    : socket_(socket),
      pre_shared_key_(pre_shared_key),
      salt_filter_(salt_filter),
      reader_(16384 + 34),
      write_buffer_(std::make_unique<uint8_t[]>(write_buffer_size_)) {}

EncryptedDatagram::EncryptedDatagram(
    udp::socket &socket,
    const proxy::shadowsocks::PreSharedKey &pre_shared_key,
    SaltFilter *salt_filter)
    : socket_(socket),
      pre_shared_key_(pre_shared_key),
      salt_filter_(salt_filter),
      read_buffer_(std::make_unique<uint8_t[]>(read_buffer_size_)),
      write_buffer_(std::make_unique<uint8_t[]>(write_buffer_size_)) {}

}  // namespace shadowsocks
}  // namespace net
