#include "net/socks/tcp-server.h"

#include <array>
#include <string_view>

#include "absl/algorithm/algorithm.h"
#include "absl/strings/str_cat.h"
#include "base/logging.h"
#include "boost/endian/conversion.hpp"
#include "boost/smart_ptr/intrusive_ptr.hpp"
#include "boost/smart_ptr/intrusive_ref_counter.hpp"
#include "net/socks/wire-structs.h"

namespace net {
namespace socks {

class TcpServer::Connection : public boost::intrusive_ref_counter<
    Connection, boost::thread_unsafe_counter>  {
public:
    explicit Connection(TcpServer &server);

    void accept();

private:
    void handshake_request();
    void handshake_dispatch();
    void handshake_reply();
    void request();
    void dispatch();
    void resolve(std::string_view host, uint16_t port);
    void connect();

    template <typename EndpointsT>
    void connect(const EndpointsT &endpoints);

    void reply();
    void forward_read();
    void forward_write();
    void forward_rate_limit();
    void backward_read();
    void backward_write();
    void backward_rate_limit();

    void close();

    TcpServer &server_;
    tcp::socket socket_;
    tcp::socket remote_socket_;
    std::unique_ptr<uint8_t[]> forward_buffer_;
    static constexpr size_t forward_buffer_size_ = 16384;
    size_t forward_read_size_;
    std::unique_ptr<uint8_t[]> backward_buffer_;
    static constexpr size_t backward_buffer_size_ = 16384;
    size_t backward_read_size_;
};

TcpServer::TcpServer(
    const any_io_executor &executor,
    const tcp::endpoint &endpoint,
    const Options &options)
    : executor_(executor),
      acceptor_(executor_, endpoint),
      resolver_(executor_) {
    if (options.forward_bytes_rate_limit) {
        forward_bytes_rate_limiter_.emplace(
            executor,
            options.forward_bytes_rate_limit,
            options.rate_limit_capacity);
    }
    if (options.backward_bytes_rate_limit) {
        backward_bytes_rate_limiter_.emplace(
            executor,
            options.backward_bytes_rate_limit,
            options.rate_limit_capacity);
    }
    accept();
}

void TcpServer::accept() {
    boost::intrusive_ptr<Connection> connection(new Connection(*this));
    connection->accept();
}

TcpServer::Connection::Connection(TcpServer &server)
    : server_(server),
      socket_(server_.executor_),
      remote_socket_(server_.executor_),
      forward_buffer_(std::make_unique<uint8_t[]>(forward_buffer_size_)),
      backward_buffer_(std::make_unique<uint8_t[]>(backward_buffer_size_)) {}

void TcpServer::Connection::accept() {
    server_.acceptor_.async_accept(
        socket_,
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec) {
            if (ec) {
                LOG(error) << "async_accept failed: " << ec;
                connection->server_.accept();
                return;
            }
            connection->socket_.set_option(tcp::no_delay(true));
            connection->handshake_request();
            // TODO(iceboy): set keep alive timer
            connection->server_.accept();
        });
}

void TcpServer::Connection::handshake_request() {
    auto *request =
        reinterpret_cast<wire::HandshakeRequest *>(forward_buffer_.get());
    request->nmethods = 0;
    async_read(
        socket_,
        buffer(forward_buffer_.get(), forward_buffer_size_),
        [request](std::error_code ec, size_t bytes_transferred) -> size_t {
            if (ec) {
                return 0;
            }
            return 2 + request->nmethods - bytes_transferred;
        },
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                connection->close();
                return;
            }
            connection->handshake_dispatch();
        });
}

void TcpServer::Connection::handshake_dispatch() {
    const auto *request =
        reinterpret_cast<wire::HandshakeRequest *>(forward_buffer_.get());
    if (request->ver != 5 || request->nmethods == 0 ||
        !absl::linear_search(
            &request->methods[0], &request->methods[request->nmethods], 0)) {
        close();
        return;
    }
    handshake_reply();
}

void TcpServer::Connection::handshake_reply() {
    auto *reply =
        reinterpret_cast<wire::HandshakeReply *>(backward_buffer_.get());
    reply->ver = 5;
    reply->method = 0;
    async_write(
        socket_,
        buffer(backward_buffer_.get(), sizeof(wire::HandshakeReply)),
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                connection->close();
                return;
            }
            connection->request();
        });
}

void TcpServer::Connection::request() {
    auto *header =
        reinterpret_cast<wire::RequestHeader *>(forward_buffer_.get());
    header->atyp = wire::AddressType::none;
    header->host_length = 0;
    async_read(
        socket_,
        buffer(forward_buffer_.get(), forward_buffer_size_),
        [header](std::error_code ec, size_t bytes_transferred) -> size_t {
            if (ec) {
                return 0;
            }
            switch (header->atyp) {
            case wire::AddressType::ipv4:
                return 10 - bytes_transferred;
            case wire::AddressType::host:
                return 7 + header->host_length - bytes_transferred;
            case wire::AddressType::ipv6:
                return 22 - bytes_transferred;
            default:
                return 4 - bytes_transferred;
            }
        },
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                connection->close();
                return;
            }
            connection->dispatch();
        });
}

void TcpServer::Connection::dispatch() {
    const auto *header =
        reinterpret_cast<wire::RequestHeader *>(forward_buffer_.get());
    switch (header->cmd) {
    case wire::Command::connect:
        connect();
        return;
    default:
        // TODO(iceboy): support other commands
        LOG(error) << "unsupported command " << static_cast<int>(header->cmd);
        close();
        return;
    }
}

void TcpServer::Connection::connect() {
    const auto *header =
        reinterpret_cast<wire::RequestHeader *>(forward_buffer_.get());
    size_t host_length;
    switch (header->atyp) {
    case wire::AddressType::ipv4:
        connect(
            std::array<tcp::endpoint, 1>{{
                tcp::endpoint(
                    address_v4(header->ipv4_address),
                    boost::endian::load_big_u16(&forward_buffer_[8]))}});
        break;
    case wire::AddressType::host:
        host_length = header->host_length;
        resolve(
            {reinterpret_cast<const char *>(&forward_buffer_[5]), host_length},
            boost::endian::load_big_u16(&forward_buffer_[host_length + 5]));
        break;
    default:
        // TODO(iceboy): support other address types
        LOG(error) << "unsupported address type "
                   << static_cast<int>(header->atyp);
        close();
        return;
    }
}

void TcpServer::Connection::resolve(std::string_view host, uint16_t port) {
    server_.resolver_.async_resolve(
        host,
        absl::StrCat(port),
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, const tcp::resolver::results_type &endpoints) {
            if (ec) {
                connection->close();
                return;
            }
            connection->connect(endpoints);
            // TODO(iceboy): update keep alive timer
        });
}

template <typename EndpointsT>
void TcpServer::Connection::connect(const EndpointsT &endpoints) {
    async_connect(
        remote_socket_,
        endpoints,
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, const tcp::endpoint &) {
            if (ec) {
                connection->close();
                return;
            }
            connection->remote_socket_.set_option(tcp::no_delay(true));
            connection->reply();
            connection->forward_read();
            // TODO(iceboy): update keep alive timer
        });
}

void TcpServer::Connection::reply() {
    auto *header =
        reinterpret_cast<wire::ReplyHeader *>(backward_buffer_.get());
    header->ver = 5;
    header->rep = wire::Reply::succeeded;
    header->rsv = 0;
    // TODO(iceboy): support other address types
    header->atyp = wire::AddressType::ipv4;
    header->ipv4_address =
        remote_socket_.local_endpoint().address().to_v4().to_bytes();
    boost::endian::store_big_u16(
        &backward_buffer_[8], remote_socket_.local_endpoint().port());
    async_write(
        socket_,
        buffer(backward_buffer_.get(), 10),
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                connection->close();
                return;
            }
            connection->backward_read();
            // TODO(iceboy): update keep alive timer
        });
}

void TcpServer::Connection::forward_read() {
    socket_.async_read_some(
        buffer(forward_buffer_.get(), forward_buffer_size_),
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                connection->close();
                return;
            }
            connection->forward_read_size_ = size;
            connection->forward_write();
            // TODO(iceboy): update keep alive timer
        });
}

void TcpServer::Connection::forward_write() {
    async_write(
        remote_socket_,
        buffer(forward_buffer_.get(), forward_read_size_),
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                connection->close();
                return;
            }
            if (connection->server_.forward_bytes_rate_limiter_) {
                connection->forward_rate_limit();
            } else {
                connection->forward_read();
            }
        });
}

void TcpServer::Connection::forward_rate_limit() {
    server_.forward_bytes_rate_limiter_->acquire(
        forward_read_size_,
        [connection = boost::intrusive_ptr<Connection>(this)]() {
            connection->forward_read();
        });
}

void TcpServer::Connection::backward_read() {
    remote_socket_.async_read_some(
        buffer(backward_buffer_.get(), backward_buffer_size_),
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                connection->close();
                return;
            }
            connection->backward_read_size_ = size;
            connection->backward_write();
            // TODO(iceboy): update keep alive timer
        });
}

void TcpServer::Connection::backward_write() {
    async_write(
        socket_,
        buffer(backward_buffer_.get(), backward_read_size_),
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                connection->close();
                return;
            }
            if (connection->server_.backward_bytes_rate_limiter_) {
                connection->backward_rate_limit();
            } else {
                connection->backward_read();
            }
        });
}

void TcpServer::Connection::backward_rate_limit() {
    server_.backward_bytes_rate_limiter_->acquire(
        backward_read_size_,
        [connection = boost::intrusive_ptr<Connection>(this)]() {
            connection->backward_read();
        });
}

void TcpServer::Connection::close() {
    remote_socket_.close();
    socket_.close();
}

}  // namespace socks
}  // namespace net
