#ifndef _NET_PROXY_SYSTEM_CONNECTOR_H
#define _NET_PROXY_SYSTEM_CONNECTOR_H

#include <chrono>

#include "net/timer-list.h"
#include "net/interface/connector.h"
#include "net/proxy/ares/resolver.h"
#include "net/proxy/system/tcp-socket-stream.h"
#include "net/proxy/system/udp-socket-datagram.h"

namespace net {
namespace proxy {
namespace system {

class Connector : public net::Connector {
public:
    struct Options {
        std::chrono::nanoseconds timeout = std::chrono::minutes(5);
        bool tcp_no_delay = true;
        bool tcp_fast_open_connect = true;
        ares::Resolver::Options resolver_options;
    };

    Connector(const any_io_executor &executor, const Options &options);

    Connector(const Connector &) = delete;
    Connector &operator=(const Connector &) = delete;

    void connect(
        const tcp::endpoint &endpoint,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    void connect(
        std::string_view host,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    std::error_code bind(
        const udp::endpoint &endpoint,
        std::unique_ptr<Datagram> &datagram) override;

    ares::Resolver &resolver() { return resolver_; }

private:
    class ConnectOperation;

    any_io_executor executor_;
    ares::Resolver resolver_;
    TimerList timer_list_;
    bool tcp_no_delay_;
    bool tcp_fast_open_connect_;
};

}  // namespace proxy
}  // namespace system
}  // namespace net

#endif  // _NET_PROXY_SYSTEM_CONNECTOR_H
