#include "net/proxy/socks/handler.h"

#include <algorithm>
#include <boost/endian/conversion.hpp>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include "absl/container/fixed_array.h"
#include "base/types.h"

namespace net {
namespace proxy {
namespace socks {

class Handler::TcpConnection : public boost::intrusive_ref_counter<
    TcpConnection, boost::thread_unsafe_counter> {
public:
    TcpConnection(
        Handler &handler,
        Stream &stream,
        absl::AnyInvocable<void(std::error_code) &&> callback);
    ~TcpConnection();

    void start() { forward_read(); }

private:
    enum class State {
        method_selection,
        request,
        connect,
    };

    void forward_read();
    void forward_dispatch();
    void method_selection();
    void request();
    void connect_ipv4(ConstBufferSpan buffer);
    void connect_ipv6(ConstBufferSpan buffer);
    void connect_host(ConstBufferSpan buffer);
    void forward_write();
    void reply();
    void backward_write();
    void backward_dispatch();
    void backward_read();

    Handler &handler_;
    Stream &stream_;
    absl::AnyInvocable<void(std::error_code) &&> callback_;
    std::unique_ptr<Stream> remote_stream_;
    State state_ = State::method_selection;
    absl::FixedArray<uint8_t, 0> forward_buffer_;
    size_t forward_size_ = 0;
    absl::FixedArray<uint8_t, 0> backward_buffer_;
    size_t backward_size_;
};

Handler::Handler(const any_io_executor &executor, proxy::Connector &connector)
    : connector_(connector) {}

void Handler::handle_stream(
    Stream &stream,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    boost::intrusive_ptr<TcpConnection> connection(new TcpConnection(
        *this, stream, std::move(callback)));
    connection->start();
}

Handler::TcpConnection::TcpConnection(
    Handler &handler,
    Stream &stream,
    absl::AnyInvocable<void(std::error_code) &&> callback)
    : handler_(handler),
      stream_(stream),
      callback_(std::move(callback)),
      // TODO: find out how to use larger buffers
      forward_buffer_(4096),
      backward_buffer_(4096) {}

Handler::TcpConnection::~TcpConnection() {
    std::move(callback_)({});
}

void Handler::TcpConnection::forward_read() {
    stream_.async_read_some(
        buffer(
            &forward_buffer_[forward_size_],
            forward_buffer_.size() - forward_size_),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                return;
            }
            connection->forward_size_ += size;
            connection->forward_dispatch();
        });
}

void Handler::TcpConnection::forward_dispatch() {
    switch (state_) {
    case State::method_selection:
        method_selection();
        break;
    case State::request:
        request();
        break;
    case State::connect:
        forward_write();
        break;
    }
}

void Handler::TcpConnection::method_selection() {
    ConstBufferSpan buffer(forward_buffer_.data(), forward_size_);
    if (buffer.size() < 2) {
        forward_read();
        return;
    }
    if (buffer[0] != 5) {
        return;
    }
    size_t nmethods = buffer[1];
    buffer.remove_prefix(2);
    if (buffer.size() < nmethods) {
        forward_read();
        return;
    }
    if (std::find(&buffer[0], &buffer[nmethods], 0) == &buffer[nmethods]) {
        return;
    }
    buffer.remove_prefix(nmethods);
    if (!buffer.empty()) {
        memmove(forward_buffer_.data(), buffer.data(), buffer.size());
    }
    forward_size_ = buffer.size();
    state_ = State::request;
    backward_buffer_[0] = 5;
    backward_buffer_[1] = 0;
    backward_size_ = 2;
    backward_write();
}

void Handler::TcpConnection::request() {
    ConstBufferSpan buffer(forward_buffer_.data(), forward_size_);
    if (buffer.size() < 4) {
        forward_read();
        return;
    }
    if (buffer[0] != 5 || buffer[1] != 1) {
        return;
    }
    switch (buffer[3]) {
    case 1:  // ipv4
        buffer.remove_prefix(4);
        connect_ipv4(buffer);
        return;
    case 4:  // ipv6
        buffer.remove_prefix(4);
        connect_ipv6(buffer);
        return;
    case 3:  // host
        buffer.remove_prefix(4);
        connect_host(buffer);
        return;
    }
}

void Handler::TcpConnection::connect_ipv4(ConstBufferSpan buffer) {
    if (buffer.size() < 6) {
        return;
    }
    address_v4::bytes_type address_bytes;
    memcpy(address_bytes.data(), &buffer[0], 4);
    uint16_t port = boost::endian::load_big_u16(&buffer[4]);
    buffer.remove_prefix(6);
    forward_size_ = 0;
    state_ = State::connect;
    handler_.connector_.connect_tcp_v4(
        address_v4(address_bytes),
        port,
        net::buffer(buffer.data(), buffer.size()),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                return;
            }
            connection->remote_stream_ = std::move(stream);
            connection->forward_read();
            connection->reply();
        });
}

void Handler::TcpConnection::connect_ipv6(ConstBufferSpan buffer) {
    if (buffer.size() < 18) {
        return;
    }
    address_v6::bytes_type address_bytes;
    memcpy(address_bytes.data(), &buffer[0], 16);
    uint16_t port = boost::endian::load_big_u16(&buffer[16]);
    buffer.remove_prefix(18);
    forward_size_ = 0;
    state_ = State::connect;
    handler_.connector_.connect_tcp_v6(
        address_v6(address_bytes),
        port,
        net::buffer(buffer.data(), buffer.size()),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                return;
            }
            connection->remote_stream_ = std::move(stream);
            connection->forward_read();
            connection->reply();
        });
}

void Handler::TcpConnection::connect_host(ConstBufferSpan buffer) {
    if (buffer.empty()) {
        return;
    }
    size_t host_length = buffer[0];
    if (buffer.size() < 1 + host_length + 2) {
        return;
    }
    std::string_view host(
        reinterpret_cast<const char *>(&buffer[1]), host_length);
    uint16_t port = boost::endian::load_big_u16(&buffer[1 + host_length]);
    buffer.remove_prefix(1 + host_length + 2);
    forward_size_ = 0;
    state_ = State::connect;
    handler_.connector_.connect_tcp_host(
        host,
        port,
        net::buffer(buffer.data(), buffer.size()),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                return;
            }
            connection->remote_stream_ = std::move(stream);
            connection->forward_read();
            connection->reply();
        });
}

void Handler::TcpConnection::forward_write() {
    async_write(
        *remote_stream_,
        buffer(forward_buffer_.data(), forward_size_),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                return;
            }
            connection->forward_size_ = 0;
            connection->forward_read();
        });
}

void Handler::TcpConnection::reply() {
    backward_buffer_[0] = 5;
    backward_buffer_[1] = 0;
    backward_buffer_[2] = 0;
    backward_buffer_[3] = 1;
    backward_buffer_[4] = 0;
    backward_buffer_[5] = 0;
    backward_buffer_[6] = 0;
    backward_buffer_[7] = 0;
    backward_buffer_[8] = 0;
    backward_buffer_[9] = 0;
    backward_size_ = 10;
    backward_write();
}

void Handler::TcpConnection::backward_write() {
    async_write(
        stream_,
        buffer(backward_buffer_.data(), backward_size_),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                return;
            }
            connection->backward_size_ = 0;
            connection->backward_dispatch();
        });
}

void Handler::TcpConnection::backward_dispatch() {
    switch (state_) {
    case State::method_selection:
    case State::request:
        forward_read();
        break;
    case State::connect:
        backward_read();
        break;
    }
}

void Handler::TcpConnection::backward_read() {
    remote_stream_->async_read_some(
        buffer(
            &backward_buffer_[backward_size_],
            backward_buffer_.size() - backward_size_),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                return;
            }
            connection->backward_size_ += size;
            connection->backward_write();
        });
}

}  // namespace socks
}  // namespace proxy
}  // namespace net
