#ifndef _NET_PROXY_CONNECTOR_H
#define _NET_PROXY_CONNECTOR_H

#include <cstdint>
#include <memory>
#include <string_view>
#include <system_error>

#include "absl/functional/any_invocable.h"
#include "net/asio.h"
#include "net/proxy/datagram.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {

class Connector {
public:
    virtual ~Connector() = default;

    virtual void connect_tcp_v4(
        const address_v4 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) = 0;

    virtual void connect_tcp_v6(
        const address_v6 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) = 0;

    virtual void connect_tcp_host(
        std::string_view host,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) = 0;

    virtual std::error_code bind_udp_v4(
        std::unique_ptr<Datagram> &datagram) = 0;

    virtual std::error_code bind_udp_v6(
        std::unique_ptr<Datagram> &datagram) = 0;
};

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_CONNECTOR_H
