#ifndef _NET_SOCKS_WIRE_STRUCTS_H
#define _NET_SOCKS_WIRE_STRUCTS_H

#include "base/packed.h"
#include "net/asio.h"

namespace net {
namespace socks {
namespace wire {

PACKED_BEGIN
struct PACKED HandshakeRequest {
    uint8_t ver;
    uint8_t nmethods;
    uint8_t methods[255];
};
PACKED_END

PACKED_BEGIN
struct PACKED HandshakeReply {
    uint8_t ver;
    uint8_t method;
};
PACKED_END

enum class Command : uint8_t {
    connect = 1,
    bind = 2,
    udp_associate = 3,
};

enum class AddressType : uint8_t {
    none = 0,
    ipv4 = 1,
    host = 3,
    ipv6 = 4,
};

PACKED_BEGIN
struct PACKED RequestHeader {
    uint8_t ver;
    Command cmd;
    uint8_t rsv;
    AddressType atyp;
    union {
        address_v4::bytes_type ipv4_address;
        uint8_t host_length;
        address_v6::bytes_type ipv6_address;
    };
};
PACKED_END

enum class Reply : uint8_t {
    succeeded = 0,
    general_failure = 1,
    connection_not_allowed = 2,
    network_unreachable = 3,
    host_unreachable = 4,
    connection_refused = 5,
    ttl_expired = 6,
    command_not_supported = 7,
    address_type_not_supported = 8,
};

PACKED_BEGIN
struct PACKED ReplyHeader {
    uint8_t ver;
    Reply rep;
    uint8_t rsv;
    AddressType atyp;
    union {
        address_v4::bytes_type ipv4_address;
        uint8_t host_length;
        address_v6::bytes_type ipv6_address;
    };
};
PACKED_END

}  // namespace wire
}  // namespace socks
}  // namespace net

#endif  // _NET_SOCKS_WIRE_STRUCTS_H
