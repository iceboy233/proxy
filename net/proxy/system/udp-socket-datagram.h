#ifndef _NET_PROXY_SYSTEM_UDP_SOCKET_DATAGRAM_H
#define _NET_PROXY_SYSTEM_UDP_SOCKET_DATAGRAM_H

#include "net/asio.h"
#include "net/proxy/datagram.h"

namespace net {
namespace proxy {
namespace system {

class UdpSocketDatagram : public Datagram {
public:
    explicit UdpSocketDatagram(const any_io_executor &executor)
        : socket_(executor) {}

    UdpSocketDatagram(const UdpSocketDatagram &) = delete;
    UdpSocketDatagram &operator=(const UdpSocketDatagram &) = delete;

    void async_receive_from(
        absl::Span<mutable_buffer const> buffers,
        udp::endpoint &endpoint,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void async_send_to(
        absl::Span<const_buffer const> buffers,
        const udp::endpoint &endpoint,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    any_io_executor get_executor() override {
        return socket_.get_executor();
    }

    udp::socket &socket() { return socket_; }
    const udp::socket &socket() const { return socket_; }

private:
    udp::socket socket_;
};

}  // namespace proxy
}  // namespace system
}  // namespace net

#endif  // _NET_PROXY_SYSTEM_UDP_SOCKET_DATAGRAM_H
