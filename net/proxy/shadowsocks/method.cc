#include "net/proxy/shadowsocks/method.h"

namespace net {
namespace proxy {
namespace shadowsocks {

const Method &Method::aes_128_gcm() {
    static Method method(EVP_aead_aes_128_gcm());
    return method;
}

const Method &Method::aes_192_gcm() {
    static Method method(EVP_aead_aes_192_gcm());
    return method;
}

const Method &Method::aes_256_gcm() {
    static Method method(EVP_aead_aes_256_gcm());
    return method;
}

const Method &Method::chacha20_ietf_poly1305() {
    static Method method(EVP_aead_chacha20_poly1305());
    return method;
}

const Method &Method::xchacha20_ietf_poly1305() {
    static Method method(EVP_aead_xchacha20_poly1305());
    return method;
}

const Method *Method::find(std::string_view name) {
    if (name == "aes-128-gcm") {
        return &aes_128_gcm();
    }
    if (name == "aes-192-gcm") {
        return &aes_192_gcm();
    }
    if (name == "aes-256-gcm") {
        return &aes_256_gcm();
    }
    if (name == "chacha20-ietf-poly1305") {
        return &chacha20_ietf_poly1305();
    }
    if (name == "xchacha20-ietf-poly1305") {
        return &xchacha20_ietf_poly1305();
    }
    return nullptr;
}

Method::Method(const EVP_AEAD *aead)
    : aead_(aead) {}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
