#ifndef _NET_PROXY_CONNECTOR_H
#define _NET_PROXY_CONNECTOR_H

#include <cstdint>
#include <memory>
#include <string_view>
#include <system_error>

#include "absl/functional/any_invocable.h"
#include "net/asio.h"
#include "net/proxy/stream.h"

namespace net {

class Connector {
public:
    virtual ~Connector() = default;

    virtual void connect_tcp(
        const address_v4 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) = 0;

    virtual void connect_tcp(
        const address_v6 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) = 0;

    virtual void connect_tcp(
        std::string_view host,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) = 0;
};

}  // namespace net

#endif  // _NET_PROXY_CONNECTOR_H
