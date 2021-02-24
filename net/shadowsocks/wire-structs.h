#ifndef _NET_SHADOWSOCKS_WIRE_STRUCTS_H
#define _NET_SHADOWSOCKS_WIRE_STRUCTS_H

#include <cstdint>

#include "base/packed.h"
#include "net/asio.h"

namespace net {
namespace shadowsocks {
namespace wire {

enum class AddressType : uint8_t {
    ipv4 = 1,
    host = 3,
    ipv6 = 4,
};

PACKED_BEGIN
struct PACKED AddressHeader {
    AddressType type;
    union {
        address_v4::bytes_type ipv4_address;
        uint8_t host_length;
        address_v6::bytes_type ipv6_address;
    };
};
PACKED_END

}  // namespace wire
}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_WIRE_STRUCTS_H
