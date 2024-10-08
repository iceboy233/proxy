#include "net/proxy/system/connector.h"

#include <array>
#include <utility>

#include "absl/strings/str_cat.h"
#include "net/proxy/util/write.h"

namespace net {
namespace proxy {
namespace system {

Connector::Connector(const any_io_executor &executor, const Options &options)
    : executor_(executor),
      resolver_(executor_, *this, options.resolver_options),
      timer_list_(executor_, options.timeout),
      tcp_no_delay_(options.tcp_no_delay) {}

void Connector::connect_tcp_v4(
    const address_v4 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    connect_tcp(
        std::array<tcp::endpoint, 1>({tcp::endpoint(address, port)}),
        initial_data,
        std::move(callback));
}

void Connector::connect_tcp_v6(
    const address_v6 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    connect_tcp(
        std::array<tcp::endpoint, 1>({tcp::endpoint(address, port)}),
        initial_data,
        std::move(callback));
}

void Connector::connect_tcp_host(
    std::string_view host,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    resolver_.resolve(
        host,
        [this, port, initial_data, callback = std::move(callback)](
            std::error_code ec, const std::vector<address> &addresses) mutable {
        if (ec) {
            std::move(callback)(ec, nullptr);
            return;
        }
        std::vector<tcp::endpoint> endpoints;
        endpoints.reserve(addresses.size());
        for (const auto &address : addresses) {
            endpoints.push_back(tcp::endpoint(address, port));
        }
        connect_tcp(endpoints, initial_data, std::move(callback));
    });
}

std::error_code Connector::bind_udp_v4(std::unique_ptr<Datagram> &datagram) {
    udp::socket socket(executor_);
    boost::system::error_code ec;
    socket.open(udp::v4(), ec);
    if (ec) {
        return ec;
    }
    datagram = std::make_unique<UdpSocketDatagram>(std::move(socket));
    return {};
}

std::error_code Connector::bind_udp_v6(std::unique_ptr<Datagram> &datagram) {
    udp::socket socket(executor_);
    boost::system::error_code ec;
    socket.open(udp::v6(), ec);
    if (ec) {
        return ec;
    }
    datagram = std::make_unique<UdpSocketDatagram>(std::move(socket));
    return {};
}

template <typename EndpointsT>
void Connector::connect_tcp(
    const EndpointsT &endpoints,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    auto stream = std::make_unique<TcpSocketStream>(
        tcp::socket(executor_), timer_list_);
    tcp::socket &socket = stream->socket();
    async_connect(
        socket,
        endpoints,
        [this, stream = std::move(stream), initial_data,
            callback = std::move(callback)](
            std::error_code ec, const tcp::endpoint &) mutable {
            if (ec) {
                std::move(callback)(ec, nullptr);
                return;
            }
            if (tcp_no_delay_) {
                stream->socket().set_option(tcp::no_delay(true));
            }
            if (initial_data.size()) {
                send_initial_data(
                    std::move(stream), initial_data, std::move(callback));
                return;
            }
            std::move(callback)({}, std::move(stream));
        });
}

void Connector::send_initial_data(
    std::unique_ptr<TcpSocketStream> stream,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    TcpSocketStream &stream_ref = *stream;
    write(
        stream_ref,
        {initial_data.data(), initial_data.size()},
        [stream = std::move(stream), callback = std::move(callback)](
            std::error_code ec) mutable {
        if (ec) {
            std::move(callback)(ec, nullptr);
            return;
        }
        std::move(callback)({}, std::move(stream));
    });
}

}  // namespace system
}  // namespace proxy
}  // namespace net
