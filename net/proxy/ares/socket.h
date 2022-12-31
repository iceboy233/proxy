#ifndef _NET_PROXY_ARES_SOCKET_H
#define _NET_PROXY_ARES_SOCKET_H

#include <ares.h>
#include <queue>
#include <vector>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include "net/asio.h"
#include "net/proxy/connector.h"
#include "net/proxy/datagram.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {
namespace ares {

class Socket : public boost::intrusive_ref_counter<
    Socket, boost::thread_unsafe_counter> {
public:
    virtual ~Socket() = default;

    virtual int connect(const sockaddr *addr, ares_socklen_t addr_len) = 0;
    virtual ares_ssize_t recvfrom(
        void *buf, size_t buf_size, int flags,
        sockaddr *addr, ares_socklen_t *addr_len) = 0;
    virtual ares_ssize_t sendv(const iovec *data, int len) = 0;
    virtual void close() = 0;
};

class TcpSocket : public Socket {
public:
    TcpSocket(
        ares_channel channel,
        ares_socket_t fd,
        const any_io_executor &executor,
        Connector &connector);

    int connect(const sockaddr *addr, ares_socklen_t addr_len) override;
    ares_ssize_t recvfrom(
        void *buf, size_t buf_size, int flags,
        sockaddr *addr, ares_socklen_t *addr_len) override;
    ares_ssize_t sendv(const iovec *data, int len) override;
    void close() override;

private:
    ares_channel channel_;
    ares_socket_t fd_;
    any_io_executor executor_;
    Connector &connector_;
    std::unique_ptr<Stream> stream_;
    std::vector<uint8_t> read_buffer_;
    size_t read_size_ = 0;
    bool read_finished_ = false;
    std::vector<uint8_t> write_buffer_;
};

class UdpSocket : public Socket {
public:
    UdpSocket(
        ares_channel channel,
        ares_socket_t fd,
        const any_io_executor &executor,
        Connector &connector);

    int connect(const sockaddr *addr, ares_socklen_t addr_len) override;
    ares_ssize_t recvfrom(
        void *buf, size_t buf_size, int flags,
        sockaddr *addr, ares_socklen_t *addr_len) override;
    ares_ssize_t sendv(const iovec *data, int len) override;
    void close() override;

private:
    void send_next();

    ares_channel channel_;
    ares_socket_t fd_;
    any_io_executor executor_;
    Connector &connector_;
    std::unique_ptr<Datagram> datagram_;
    std::vector<uint8_t> receive_buffer_;
    size_t receive_size_ = 0;
    udp::endpoint receive_endpoint_;
    bool receive_finished_ = false;
    std::queue<std::vector<uint8_t>> send_queue_;
    udp::endpoint send_endpoint_;
};

}  // namespace ares
}  // namespace proxy
}  // namespace net

#endif  // _NET_ARES_SOCKET_H
