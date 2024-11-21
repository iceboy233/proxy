#ifndef _NET_PROXY_SYSTEM_TCP_SOCKET_STREAM_H
#define _NET_PROXY_SYSTEM_TCP_SOCKET_STREAM_H

#include "net/asio.h"
#include "net/timer-list.h"
#include "net/interface/stream.h"

namespace net {
namespace proxy {
namespace system {

class TcpSocketStream : public Stream {
public:
    TcpSocketStream(tcp::socket socket, TimerList &timer_list);

    TcpSocketStream(const TcpSocketStream &) = delete;
    TcpSocketStream &operator=(const TcpSocketStream &) = delete;

    void read(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void write(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void close() override;

    tcp::socket &socket() { return socket_; }
    const tcp::socket &socket() const { return socket_; }

private:
    tcp::socket socket_;
    TimerList::Timer timer_;
};

}  // namespace proxy
}  // namespace system
}  // namespace net

#endif  // _NET_PROXY_SYSTEM_TCP_SOCKET_STREAM_H
