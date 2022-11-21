#ifndef _NET_PROXY_SYSTEM_H
#define _NET_PROXY_SYSTEM_H

#include "net/proxy/connector.h"

namespace net {

class SystemConnector : public Connector {
public:
    explicit SystemConnector(const any_io_executor &executor);

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

private:
    class TcpSocketStream;
    class UdpSocketDatagram;

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
    tcp::resolver resolver_;
};

}  // namespace net

#endif  // _NET_PROXY_SYSTEM_H
