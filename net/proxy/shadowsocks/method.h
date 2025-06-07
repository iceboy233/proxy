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
    static const Method &_2022_blake3_aes_128_gcm();
    static const Method &_2022_blake3_aes_192_gcm();
    static const Method &_2022_blake3_aes_256_gcm();
    static const Method &_2022_blake3_chacha20_poly1305();
    static const Method &_2022_blake3_xchacha20_poly1305();
    static const Method *find(std::string_view name);

    size_t key_size() const { return EVP_AEAD_key_length(aead_); }
    size_t salt_size() const { return EVP_AEAD_key_length(aead_); }
    size_t nonce_size() const { return EVP_AEAD_nonce_length(aead_); }
    size_t max_chunk_size() const { return is_spec_2022_ ? 65535 : 16383; }
    size_t buffer_size_hint() const { return is_spec_2022_ ? 65535 : 65532; }
    bool is_spec_2022() const { return is_spec_2022_; }

private:
    Method(const EVP_AEAD *aead, bool is_spec_2022);

    friend class SessionSubkey;

    const EVP_AEAD *aead_;
    bool is_spec_2022_;
};

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SHADOWSOCKS_METHOD_H
