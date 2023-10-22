#ifndef _NET_PROXY_SYSTEM_CONNECTOR_H
#define _NET_PROXY_SYSTEM_CONNECTOR_H

#include <chrono>

#include "net/proxy/ares/resolver.h"
#include "net/proxy/connector.h"
#include "net/proxy/system/tcp-socket-stream.h"
#include "net/proxy/system/udp-socket-datagram.h"
#include "net/timer-list.h"

namespace net {
namespace proxy {
namespace system {

class Connector : public proxy::Connector {
public:
    struct Options {
        std::chrono::nanoseconds timeout = std::chrono::minutes(5);
        bool tcp_no_delay = true;
        ares::Resolver::Options resolver_options;
    };

    Connector(const any_io_executor &executor, const Options &options);

    Connector(const Connector &) = delete;
    Connector &operator=(const Connector &) = delete;

    void connect_tcp_v4(
        const address_v4 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    void connect_tcp_v6(
        const address_v6 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    void connect_tcp_host(
        std::string_view host,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    std::error_code bind_udp_v4(std::unique_ptr<Datagram> &datagram) override;
    std::error_code bind_udp_v6(std::unique_ptr<Datagram> &datagram) override;

    ares::Resolver &resolver() { return resolver_; }

private:
    template <typename EndpointsT>
    void connect_tcp(
        const EndpointsT &endpoints,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback);

    static void send_initial_data(
        std::unique_ptr<TcpSocketStream> stream,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback);

    any_io_executor executor_;
    ares::Resolver resolver_;
    TimerList timer_list_;
    bool tcp_no_delay_;
};

}  // namespace proxy
}  // namespace system
}  // namespace net

#endif  // _NET_PROXY_SYSTEM_CONNECTOR_H
