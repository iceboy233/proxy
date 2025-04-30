#include "net/proxy/shadowsocks/session-subkey.h"

#include <blake3.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <string_view>

#include "base/logging.h"

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
    const PreSharedKey &psk, const uint8_t *salt) {
    memcpy(salt_.data(), salt, psk.method().salt_size());
    std::array<uint8_t, 32> key;
    if (psk.method().is_spec_2022()) {
        blake3_hasher hasher;
        constexpr std::string_view info = "shadowsocks 2022 session subkey";
        blake3_hasher_init_derive_key_raw(&hasher, info.data(), info.size());
        blake3_hasher_update(&hasher, psk.data(), psk.size());
        blake3_hasher_update(&hasher, salt_.data(), psk.method().salt_size());
        blake3_hasher_finalize(&hasher, key.data(), psk.size());
    } else {
        constexpr std::string_view info = "ss-subkey";
        if (!HKDF(
            key.data(), psk.size(), EVP_sha1(), psk.data(), psk.size(),
            salt_.data(), psk.method().salt_size(),
            reinterpret_cast<const uint8_t *>(info.data()), info.size())) {
            LOG(fatal) << "HKDF failed";
            abort();
        }
    }
    if (!EVP_AEAD_CTX_init(
        &aead_ctx_, psk.method().aead_, key.data(), psk.size(), 16, nullptr)) {
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
