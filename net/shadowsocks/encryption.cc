#include "net/shadowsocks/encryption.h"

#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/md5.h>
#include <openssl/siphash.h>
#include <cstdlib>

#include "base/logging.h"
#include "boost/container/flat_map.hpp"

namespace net {
namespace shadowsocks {
namespace {

const boost::container::flat_map<std::string_view, const EVP_AEAD *> aeads = {{
    {"aes-128-gcm", EVP_aead_aes_128_gcm()},
    {"aes-192-gcm", EVP_aead_aes_192_gcm()},
    {"aes-256-gcm", EVP_aead_aes_256_gcm()},
    {"chacha20-ietf-poly1305", EVP_aead_chacha20_poly1305()},
    {"xchacha20-ietf-poly1305", EVP_aead_xchacha20_poly1305()},
}};

}  // namespace

void MasterKey::init(std::string_view method, std::string_view password) {
    auto iter = aeads.find(method);
    if (iter == aeads.end()) {
        LOG(fatal) << "invalid method: " << method;
        abort();
    }
    aead_ = iter->second;
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, password.data(), password.size());
    MD5_Final(&key_[0], &ctx);
    if (size() > 16) {
        MD5_Init(&ctx);
        MD5_Update(&ctx, &key_[0], 16);
        MD5_Update(&ctx, password.data(), password.size());
        MD5_Final(&key_[16], &ctx);
    }
}

SessionKey::SessionKey(const MasterKey &master_key, const uint8_t *salt) {
    std::array<uint8_t, 32> key;
    size_t key_size = EVP_AEAD_key_length(master_key.aead());
    if (!HKDF(
        key.data(), key_size, EVP_sha1(), master_key.data(), master_key.size(),
        salt, key_size, reinterpret_cast<const uint8_t *>("ss-subkey"), 9)) {
        LOG(fatal) << "HKDF failed";
        abort();
    }
    if (!EVP_AEAD_CTX_init(
        &aead_ctx_, master_key.aead(), key.data(), key_size, 16, nullptr)) {
        LOG(fatal) << "EVP_AEAD_CTX_init failed";
        abort();
    }
}

SessionKey::~SessionKey() {
    EVP_AEAD_CTX_cleanup(&aead_ctx_);
}

void SessionKey::encrypt(
    absl::Span<const uint8_t> in, uint8_t *out, uint8_t out_tag[16]) {
    size_t out_tag_len;
    if (!EVP_AEAD_CTX_seal_scatter(
        &aead_ctx_, out, out_tag, &out_tag_len, 16,
        reinterpret_cast<uint8_t *>(&nonce_),
        EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(&aead_ctx_)),
        in.data(), in.size(), nullptr, 0, nullptr, 0) ||
        out_tag_len != 16) {
        LOG(fatal) << "EVP_AEAD_CTX_seal_scatter failed";
        abort();
    }
    ++nonce_[0] || ++nonce_[1] || ++nonce_[2];
}

bool SessionKey::decrypt(
    absl::Span<const uint8_t> in, const uint8_t in_tag[16], uint8_t *out) {
    if (!EVP_AEAD_CTX_open_gather(
        &aead_ctx_, out, reinterpret_cast<uint8_t *>(&nonce_),
        EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(&aead_ctx_)),
        in.data(), in.size(), in_tag, 16, nullptr, 0)) {
        return false;
    }
    ++nonce_[0] || ++nonce_[1] || ++nonce_[2];
    return true;
}

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
    tcp::socket &socket, const MasterKey &master_key, SaltFilter *salt_filter)
    : socket_(socket),
      master_key_(master_key),
      salt_filter_(salt_filter),
      read_buffer_(std::make_unique<uint8_t[]>(read_buffer_size_)),
      write_buffer_(std::make_unique<uint8_t[]>(write_buffer_size_)) {}

EncryptedDatagram::EncryptedDatagram(
    udp::socket &socket, const MasterKey &master_key, SaltFilter *salt_filter)
    : socket_(socket),
      master_key_(master_key),
      salt_filter_(salt_filter),
      read_buffer_(std::make_unique<uint8_t[]>(read_buffer_size_)),
      write_buffer_(std::make_unique<uint8_t[]>(write_buffer_size_)) {}

}  // namespace shadowsocks
}  // namespace net
