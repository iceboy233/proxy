#include "net/proxy/ares/socket.h"

#include <utility>

#include "net/proxy/util/write.h"

#ifdef _WIN32
struct iovec {
    void *iov_base;
    size_t iov_len;
};

#define SET_ERRNO(x) WSASetLastError(WSA##x)
#else
#define SET_ERRNO(x) (errno = (x))
#endif

namespace net {
namespace proxy {
namespace ares {
namespace {

bool parse_addr(
    const sockaddr *addr, ares_socklen_t addr_len,
    address &address, uint16_t &port) {
    if (addr->sa_family == AF_INET) {
        if (addr_len < sizeof(sockaddr_in)) {
            return false;
        }
        const auto *addr4 = reinterpret_cast<const sockaddr_in *>(addr);
        address_v4::bytes_type bytes;
        memcpy(bytes.data(), &addr4->sin_addr, 4);
        address = address_v4(bytes);
        port = ntohs(addr4->sin_port);
        return true;
    } else if (addr->sa_family == AF_INET6) {
        if (addr_len < sizeof(sockaddr_in6)) {
            return false;
        }
        const auto *addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
        address_v6::bytes_type bytes;
        memcpy(bytes.data(), &addr6->sin6_addr, 16);
        address = address_v6(bytes);
        port = ntohs(addr6->sin6_port);
        return true;
    } else {
        return false;
    }
}

bool populate_addr(
    const address &address, uint16_t port,
    sockaddr *addr, ares_socklen_t *addr_len) {
    if (address.is_v4()) {
        if (*addr_len < sizeof(sockaddr_in)) {
            return false;
        }
        auto *addr4 = reinterpret_cast<sockaddr_in *>(addr);
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
        memcpy(&addr4->sin_addr, address.to_v4().to_bytes().data(), 4);
        *addr_len = sizeof(sockaddr_in);
        return true;
    } else {
        if (*addr_len < sizeof(sockaddr_in6)) {
            return false;
        }
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(addr);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);
        memcpy(&addr6->sin6_addr, address.to_v6().to_bytes().data(), 16);
        *addr_len = sizeof(sockaddr_in6);
        return true;
    }
}

}  // namespace

TcpSocket::TcpSocket(
    ares_channel channel,
    ares_socket_t fd,
    const any_io_executor &executor,
    Connector &connector)
    : channel_(channel),
      fd_(fd),
      executor_(executor),
      connector_(connector) {}

int TcpSocket::connect(const sockaddr *addr, ares_socklen_t addr_len) {
    address address;
    uint16_t port;
    if (!parse_addr(addr, addr_len, address, port)) {
        SET_ERRNO(EINVAL);
        return -1;
    }
    auto callback = [socket = boost::intrusive_ptr<TcpSocket>(this)](
        std::error_code ec, std::unique_ptr<Stream> stream) {
        if (!ec) {
            socket->stream_ = std::move(stream);
        }
        ares_process_fd(socket->channel_, socket->fd_, socket->fd_);
    };
    if (address.is_v4()) {
        connector_.connect_tcp_v4(
            address.to_v4(), port, {}, std::move(callback));
    } else {
        connector_.connect_tcp_v6(
            address.to_v6(), port, {}, std::move(callback));
    }
    SET_ERRNO(EINPROGRESS);
    return -1;
}

ares_ssize_t TcpSocket::recvfrom(
    void *buf, size_t buf_size, int flags,
    sockaddr *addr, ares_socklen_t *addr_len) {
    if (read_finished_) {
        if (buf_size < read_size_) {
            return -1;
        }
        memcpy(buf, read_buffer_.data(), read_size_);
        read_buffer_.clear();
        read_finished_ = false;
        post(executor_, [socket = boost::intrusive_ptr<TcpSocket>(this)]() {
            ares_process_fd(socket->channel_, socket->fd_, ARES_SOCKET_BAD);
        });
        return read_size_;
    }
    if (!read_buffer_.empty()) {
        SET_ERRNO(EWOULDBLOCK);
        return -1;
    }
    if (!stream_) {
        SET_ERRNO(ENETUNREACH);
        return -1;
    }
    read_buffer_.resize(buf_size);
    stream_->read(
        {{read_buffer_.data(), buf_size}},
        [socket = boost::intrusive_ptr<TcpSocket>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                socket->stream_.reset();
            }
            socket->read_size_ = size;
            socket->read_finished_ = true;
            ares_process_fd(socket->channel_, socket->fd_, ARES_SOCKET_BAD);
        });
    SET_ERRNO(EWOULDBLOCK);
    return -1;
}

ares_ssize_t TcpSocket::sendv(const iovec *data, int len) {
    if (!write_buffer_.empty()) {
        SET_ERRNO(EWOULDBLOCK);
        return -1;
    }
    for (const auto *p = data; p < data + len; ++p) {
        size_t offset = write_buffer_.size();
        write_buffer_.resize(offset + p->iov_len);
        memcpy(&write_buffer_[offset], p->iov_base, p->iov_len);
    }
    if (!stream_) {
        SET_ERRNO(ENETUNREACH);
        return -1;
    }
    write(
        *stream_,
        write_buffer_,
        [socket = boost::intrusive_ptr<TcpSocket>(this)](std::error_code ec) {
            if (ec) {
                socket->stream_.reset();
            }
            socket->write_buffer_.clear();
            ares_process_fd(socket->channel_, ARES_SOCKET_BAD, socket->fd_);
        });
    return write_buffer_.size();
}

void TcpSocket::close() {
    stream_.reset();
}

UdpSocket::UdpSocket(
    ares_channel channel,
    ares_socket_t fd,
    const any_io_executor &executor,
    Connector &connector)
    : channel_(channel),
      fd_(fd),
      executor_(executor),
      connector_(connector) {}

int UdpSocket::connect(const sockaddr *addr, ares_socklen_t addr_len) {
    address address;
    uint16_t port;
    if (!parse_addr(addr, addr_len, address, port)) {
        SET_ERRNO(EINVAL);
        return -1;
    }
    if (address.is_v4()) {
        if (connector_.bind_udp_v4(datagram_)) {
            return -1;
        }
    } else {
        if (connector_.bind_udp_v6(datagram_)) {
            return -1;
        }
    }
    send_endpoint_ = udp::endpoint(address, port);
    post(executor_, [socket = boost::intrusive_ptr<UdpSocket>(this)]() {
        ares_process_fd(socket->channel_, socket->fd_, socket->fd_);
    });
    return 0;
}

ares_ssize_t UdpSocket::recvfrom(
    void *buf, size_t buf_size, int flags,
    sockaddr *addr, ares_socklen_t *addr_len) {
    if (!datagram_) {
        SET_ERRNO(ENETUNREACH);
        return -1;
    }
    if (receive_finished_) {
        if (buf_size < receive_size_) {
            return -1;
        }
        memcpy(buf, receive_buffer_.data(), receive_size_);
        populate_addr(
            receive_endpoint_.address(), receive_endpoint_.port(),
            addr, addr_len);
        receive_buffer_.clear();
        receive_finished_ = false;
        post(executor_, [socket = boost::intrusive_ptr<UdpSocket>(this)]() {
            ares_process_fd(socket->channel_, socket->fd_, ARES_SOCKET_BAD);
        });
        return receive_size_;
    }
    if (!receive_buffer_.empty()) {
        SET_ERRNO(EWOULDBLOCK);
        return -1;
    }
    receive_buffer_.resize(buf_size);
    datagram_->receive_from(
        {{receive_buffer_.data(), buf_size}},
        receive_endpoint_,
        [socket = boost::intrusive_ptr<UdpSocket>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                socket->datagram_.reset();
            }
            socket->receive_size_ = size;
            socket->receive_finished_ = true;
            ares_process_fd(socket->channel_, socket->fd_, ARES_SOCKET_BAD);
        });
    SET_ERRNO(EWOULDBLOCK);
    return -1;
}

ares_ssize_t UdpSocket::sendv(const iovec *data, int len) {
    if (!datagram_) {
        SET_ERRNO(ENETUNREACH);
        return -1;
    }
    std::vector<uint8_t> buffer;
    for (const auto *p = data; p < data + len; ++p) {
        size_t offset = buffer.size();
        buffer.resize(offset + p->iov_len);
        memcpy(&buffer[offset], p->iov_base, p->iov_len);
    }
    size_t send_size = buffer.size();
    send_queue_.push(std::move(buffer));
    if (send_queue_.size() == 1) {
        send_next();
    }
    return send_size;
}

void UdpSocket::send_next() {
    if (!datagram_) {
        return;
    }
    datagram_->send_to(
        {{send_queue_.front().data(), send_queue_.front().size()}},
        send_endpoint_,
        [socket = boost::intrusive_ptr<UdpSocket>(this)](
            std::error_code, size_t) {
            socket->send_queue_.pop();
            if (!socket->send_queue_.empty()) {
                socket->send_next();
            } else {
                ares_process_fd(socket->channel_, ARES_SOCKET_BAD, socket->fd_);
            }
        });
}

void UdpSocket::close() {
    datagram_.reset();
}

}  // namespace ares
}  // namespace proxy
}  // namespace net
