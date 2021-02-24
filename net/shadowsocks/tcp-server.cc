#include "net/shadowsocks/tcp-server.h"

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>

#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "base/logging.h"
#include "boost/smart_ptr/intrusive_ptr.hpp"
#include "boost/smart_ptr/intrusive_ref_counter.hpp"
#include "net/shadowsocks/wire-structs.h"

namespace net {
namespace shadowsocks {

class TcpServer::Connection : public boost::intrusive_ref_counter<
    Connection, boost::thread_unsafe_counter> {
public:
    explicit Connection(TcpServer &server);

    void accept();

private:
    void forward_read();
    void forward_dispatch(absl::Span<const uint8_t> chunk);
    void forward_resolve(
        std::string_view host,
        uint16_t port,
        absl::Span<const uint8_t> initial_data);

    template <typename EndpointsT>
    void forward_connect(
        const EndpointsT &endpoints,
        absl::Span<const uint8_t> initial_data);

    void forward_write(absl::Span<const uint8_t> chunk);
    void backward_read();
    void backward_write();
    void close();

    TcpServer &server_;
    tcp::socket socket_;
    std::unique_ptr<AeadStream> crypto_stream_;
    std::optional<tcp::socket> remote_socket_;
    std::unique_ptr<uint8_t[]> backward_buffer_;
    static constexpr size_t backward_buffer_size_ = 16383;
    size_t backward_read_size_;
    // TODO(iceboy): timeout
};

TcpServer::TcpServer(
    const any_io_executor &executor,
    const tcp::endpoint &endpoint,
    std::unique_ptr<AeadFactory> crypto_factory)
    : executor_(executor),
      crypto_factory_(std::move(crypto_factory)),
      acceptor_(executor_, endpoint),
      resolver_(executor_) {
    accept();
}

void TcpServer::accept() {
    boost::intrusive_ptr<Connection> connection(new Connection(*this));
    connection->accept();
}

TcpServer::Connection::Connection(TcpServer &server)
    : server_(server),
      socket_(server_.executor_),
      backward_buffer_(std::make_unique<uint8_t[]>(backward_buffer_size_)) {
    crypto_stream_ = server.crypto_factory_->new_crypto_stream(socket_);
}

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
            connection->forward_read();
            connection->server_.accept();
        });
}

void TcpServer::Connection::forward_read() {
    crypto_stream_->read(
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, absl::Span<const uint8_t> chunk) {
            if (ec) {
                connection->close();
                return;
            }
            connection->forward_dispatch(chunk);
        });
}

void TcpServer::Connection::forward_dispatch(absl::Span<const uint8_t> chunk) {
    if (remote_socket_) {
        forward_write(chunk);
        return;
    }

    // Parse address, assuming the whole address is in the first chunk.
    if (chunk.size() < 1) {
        return;
    }
    const auto *header =
        reinterpret_cast<const wire::AddressHeader *>(chunk.data());
    size_t host_length;
    switch (chunk[0]) {
    case 1:
        if (chunk.size() < 7) {
            return;
        }
        forward_connect(
            std::array<tcp::endpoint, 1>{{
                tcp::endpoint(
                    address_v4(header->ipv4_address),
                    (chunk[5]) << 8 | chunk[6])}},
            chunk.subspan(7));
        break;
    case 3:
        if (chunk.size() < 2) {
            return;
        }
        host_length = header->host_length;
        if (chunk.size() < host_length + 4) {
            return;
        }
        forward_resolve(
            {reinterpret_cast<const char *>(&chunk[2]), host_length},
            (chunk[host_length + 2]) << 8 | chunk[host_length + 3],
            chunk.subspan(host_length + 4));
        break;
    case 4:
        if (chunk.size() < 19) {
            return;
        }
        forward_connect(
            std::array<tcp::endpoint, 1>{{
                tcp::endpoint(
                    address_v6(header->ipv6_address),
                    (chunk[17]) << 8 | chunk[18])}},
            chunk.subspan(19));
        break;
    default:
        return;
    }
}

void TcpServer::Connection::forward_resolve(
    std::string_view host,
    uint16_t port,
    absl::Span<const uint8_t> initial_data) {
    server_.resolver_.async_resolve(
        host,
        absl::StrCat(port),
        [connection = boost::intrusive_ptr<Connection>(this), initial_data](
            std::error_code ec, const tcp::resolver::results_type &endpoints) {
            if (ec) {
                connection->close();
                return;
            }
            connection->forward_connect(endpoints, initial_data);
        });
}

template <typename EndpointsT>
void TcpServer::Connection::forward_connect(
    const EndpointsT &endpoints,
    absl::Span<const uint8_t> initial_data) {
    remote_socket_.emplace(server_.executor_);
    async_connect(
        *remote_socket_,
        endpoints,
        [connection = boost::intrusive_ptr<Connection>(this), initial_data](
            std::error_code ec, const tcp::endpoint &) {
            if (ec) {
                connection->close();
                return;
            }
            connection->remote_socket_->set_option(tcp::no_delay(true));
            if (!initial_data.empty()) {
                connection->forward_write(initial_data);
            } else {
                connection->forward_read();
            }
            connection->backward_read();
        });
}

void TcpServer::Connection::forward_write(absl::Span<const uint8_t> chunk) {
    async_write(
        *remote_socket_,
        buffer(chunk.data(), chunk.size()),
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                connection->close();
                return;
            }
            connection->forward_read();
        });
}

void TcpServer::Connection::backward_read() {
    remote_socket_->async_read_some(
        buffer(backward_buffer_.get(), backward_buffer_size_),
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                connection->close();
                return;
            }
            connection->backward_read_size_ = size;
            connection->backward_write();
        });
}

void TcpServer::Connection::backward_write() {
    crypto_stream_->write(
        {backward_buffer_.get(), backward_read_size_},
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec) {
            if (ec) {
                connection->close();
                return;
            }
            connection->backward_read();
        });
}

void TcpServer::Connection::close() {
    if (remote_socket_) {
        remote_socket_->close();
    }
    socket_.close();
}

}  // namespace shadowsocks
}  // namespace net
