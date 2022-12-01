#ifndef _NET_PROXY_SHADOWSOCKS_SALT_FILTER_H
#define _NET_PROXY_SHADOWSOCKS_SALT_FILTER_H

#include <array>
#include <cstdint>

#include "base/types.h"
#include "util/hash-filter.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class SaltFilter {
public:
    SaltFilter();
    bool test_and_insert(ConstBufferSpan salt);
    void insert(ConstBufferSpan salt);

private:
    void insert(uint64_t fingerprint);

    util::HashFilter32 filter0_;
    util::HashFilter32 filter1_;
    std::array<uint64_t, 2> key_;
};

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SHADOWSOCKS_SALT_FILTER_H
