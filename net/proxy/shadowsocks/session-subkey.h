#ifndef _NET_PROXY_SHADOWSOCKS_SESSION_SUBKEY_H
#define _NET_PROXY_SHADOWSOCKS_SESSION_SUBKEY_H

#include <openssl/aead.h>
#include <array>
#include <cstdint>
#include <boost/endian/arithmetic.hpp>

#include "base/types.h"
#include "net/proxy/shadowsocks/pre-shared-key.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class SessionSubkey {
public:
    SessionSubkey();
    ~SessionSubkey();

    SessionSubkey(const SessionSubkey &) = delete;
    SessionSubkey &operator=(const SessionSubkey &) = delete;

    void init(const PreSharedKey &psk, const uint8_t *salt);

    void encrypt(ConstBufferSpan in, uint8_t *out, uint8_t out_tag[16]);
    bool decrypt(ConstBufferSpan in, const uint8_t in_tag[16], uint8_t *out);

    const uint8_t *salt() const { return salt_.data(); }

private:
    EVP_AEAD_CTX aead_ctx_;
    std::array<uint8_t, 32> salt_;
    std::array<boost::endian::little_uint64_t, 3> nonce_ = {};
    static_assert(sizeof(nonce_) == 24);
};

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SHADOWSOCKS_SESSION_SUBKEY_H
