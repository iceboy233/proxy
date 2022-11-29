#ifndef _NET_PROXY_SYSTEM_TCP_SOCKET_STREAM_H
#define _NET_PROXY_SYSTEM_TCP_SOCKET_STREAM_H

#include "net/asio.h"
#include "net/proxy/stream.h"
#include "net/timer-list.h"

namespace net {
namespace proxy {
namespace system {

class TcpSocketStream : public Stream {
public:
    TcpSocketStream(tcp::socket socket, TimerList &timer_list);

    TcpSocketStream(const TcpSocketStream &) = delete;
    TcpSocketStream &operator=(const TcpSocketStream &) = delete;

    any_io_executor get_executor() override {
        return socket_.get_executor();
    }

    void async_read_some(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void async_write_some(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;
    
    using Stream::async_read_some;
    using Stream::async_write_some;

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
