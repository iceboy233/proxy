#ifndef _NET_PROXY_SHADOWSOCKS_PRE_SHARED_KEY_H
#define _NET_PROXY_SHADOWSOCKS_PRE_SHARED_KEY_H

#include <array>
#include <cstdint>
#include <string_view>

#include "net/proxy/shadowsocks/method.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class PreSharedKey {
public:
    bool init(const Method &method, std::string_view password);

    const Method &method() const { return *method_; }
    const uint8_t *data() const { return material_.data(); }
    size_t size() const { return method_->key_size(); }

private:
    const Method *method_;
    std::array<uint8_t, 32> material_;
};

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SHADOWSOCKS_PRE_SHARED_KEY_H
