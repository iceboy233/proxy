#include "net/proxy/shadowsocks/session-subkey.h"

#include <openssl/evp.h>
#include <openssl/hkdf.h>

#include "base/logging.h"
#include "third_party/blake3/blake3.h"

namespace net {
namespace proxy {
namespace shadowsocks {

SessionSubkey::SessionSubkey() {
    EVP_AEAD_CTX_zero(&aead_ctx_);
}

SessionSubkey::~SessionSubkey() {
    EVP_AEAD_CTX_cleanup(&aead_ctx_);
}

void SessionSubkey::init(
    const PreSharedKey &pre_shared_key, const uint8_t *salt) {
    memcpy(salt_.data(), salt, pre_shared_key.method().salt_size());
    std::array<uint8_t, 32> key;
    if (pre_shared_key.method().is_spec_2022()) {
        blake3_hasher hasher;
        blake3_hasher_init_derive_key_raw(
            &hasher, "shadowsocks 2022 session subkey", 31);
        blake3_hasher_update(
            &hasher, pre_shared_key.data(), pre_shared_key.size());
        blake3_hasher_update(
            &hasher, salt_.data(), pre_shared_key.method().salt_size());
        blake3_hasher_finalize(&hasher, key.data(), pre_shared_key.size());
    } else {
        if (!HKDF(
            key.data(), pre_shared_key.size(), EVP_sha1(),
            pre_shared_key.data(), pre_shared_key.size(),
            salt_.data(), pre_shared_key.method().salt_size(),
            reinterpret_cast<const uint8_t *>("ss-subkey"), 9)) {
            LOG(fatal) << "HKDF failed";
            abort();
        }
    }
    if (!EVP_AEAD_CTX_init(
        &aead_ctx_, pre_shared_key.method().aead_,
        key.data(), pre_shared_key.size(), 16, nullptr)) {
        LOG(fatal) << "EVP_AEAD_CTX_init failed";
        abort();
    }
}

void SessionSubkey::encrypt(
    ConstBufferSpan in, uint8_t *out, uint8_t out_tag[16]) {
    size_t out_tag_len;
    if (!EVP_AEAD_CTX_seal_scatter(
        &aead_ctx_, out, out_tag, &out_tag_len, 16,
        reinterpret_cast<uint8_t *>(nonce_.data()),
        EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(&aead_ctx_)),
        in.data(), in.size(), nullptr, 0, nullptr, 0) ||
        out_tag_len != 16) {
        LOG(fatal) << "EVP_AEAD_CTX_seal_scatter failed";
        abort();
    }
    ++nonce_[0] || ++nonce_[1] || ++nonce_[2];
}

bool SessionSubkey::decrypt(
    ConstBufferSpan in, const uint8_t in_tag[16], uint8_t *out) {
    if (!EVP_AEAD_CTX_open_gather(
        &aead_ctx_, out, reinterpret_cast<uint8_t *>(nonce_.data()),
        EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(&aead_ctx_)),
        in.data(), in.size(), in_tag, 16, nullptr, 0)) {
        return false;
    }
    ++nonce_[0] || ++nonce_[1] || ++nonce_[2];
    return true;
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
