#ifndef _NET_PROXY_SHADOWSOCKS_METHOD_H
#define _NET_PROXY_SHADOWSOCKS_METHOD_H

#include <openssl/aead.h>
#include <cstddef>
#include <string_view>

namespace net {
namespace proxy {
namespace shadowsocks {

class Method {
public:
    static const Method &aes_128_gcm();
    static const Method &aes_192_gcm();
    static const Method &aes_256_gcm();
    static const Method &chacha20_ietf_poly1305();
    static const Method &xchacha20_ietf_poly1305();
    static const Method *find(std::string_view name);

    size_t key_size() const { return EVP_AEAD_key_length(aead_); }
    size_t salt_size() const { return EVP_AEAD_key_length(aead_); }
    size_t nonce_size() const { return EVP_AEAD_nonce_length(aead_); }
    size_t max_chunk_size() const { return 16383; }

private:
    explicit Method(const EVP_AEAD *aead);

    friend class SessionSubkey;

    const EVP_AEAD *aead_;
};

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SHADOWSOCKS_METHOD_H
