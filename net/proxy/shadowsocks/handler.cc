#include "net/proxy/shadowsocks/handler.h"

#include <algorithm>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include "absl/base/attributes.h"
#include "absl/container/fixed_array.h"
#include "net/proxy/shadowsocks/decryptor.h"
#include "net/proxy/shadowsocks/encryptor.h"

namespace net {
namespace proxy {
namespace shadowsocks {

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
    void forward_read();
    void forward_parse();
    void forward_parse_ipv4(size_t header_length);
    void forward_parse_ipv6(size_t header_length);
    void forward_parse_host(size_t header_length);
    void forward_write();
    void backward_read();
    void backward_write();

    enum class ReadState {
        init,
        header_length,
        header_payload,
        length,
        payload,
    };

    Handler &handler_;
    Stream &stream_;
    absl::AnyInvocable<void(std::error_code) &&> callback_;
    std::unique_ptr<Stream> remote_stream_;
    Encryptor encryptor_;
    Decryptor decryptor_;
    ReadState read_state_ = ReadState::init;
    uint16_t read_length_;
    ConstBufferSpan read_buffer_;
    absl::FixedArray<uint8_t, 0> backward_read_buffer_;
    size_t backward_read_size_;
};

Handler::Handler(
    const any_io_executor &executor,
    proxy::Connector &connector)
    : connector_(connector) {}

bool Handler::init(const Config &config) {
    return pre_shared_key_.init(*config.method, config.password);
}

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
      // TODO: find out how to use larger buffer
      backward_read_buffer_(4096) {}

Handler::TcpConnection::~TcpConnection() {
    std::move(callback_)({});
}

void Handler::TcpConnection::forward_read() {
    BufferSpan read_buffer = decryptor_.buffer();
    stream_.async_read_some(
        buffer(read_buffer.data(), read_buffer.size()),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                return;
            }
            connection->decryptor_.advance(size);
            connection->forward_parse();
        });
}

void Handler::TcpConnection::forward_parse() {
    switch (read_state_) {
    case ReadState::init:
        if (!decryptor_.init(handler_.pre_shared_key_)) {
            forward_read();
            return;
        }
        read_state_ = ReadState::header_length;
        ABSL_FALLTHROUGH_INTENDED;
    case ReadState::header_length:
        if (!decryptor_.start_chunk(2)) {
            forward_read();
            return;
        }
        read_length_ = decryptor_.pop_big_u16();
        decryptor_.finish_chunk();
        read_state_ = ReadState::header_payload;
        ABSL_FALLTHROUGH_INTENDED;
    case ReadState::header_payload:
        if (!decryptor_.start_chunk(read_length_)) {
            forward_read();
            return;
        }
        switch (decryptor_.pop_u8()) {
        case 1:  // ipv4
            forward_parse_ipv4(read_length_);
            return;
        case 4:  // ipv6
            forward_parse_ipv6(read_length_);
            return;
        case 3:  // host
            forward_parse_host(read_length_);
            return;
        default:
            return;
        }
        ABSL_FALLTHROUGH_INTENDED;
    case ReadState::length:
        if (!decryptor_.start_chunk(2)) {
            forward_read();
            return;
        }
        read_length_ = decryptor_.pop_big_u16();
        decryptor_.finish_chunk();
        read_state_ = ReadState::payload;
        ABSL_FALLTHROUGH_INTENDED;
    case ReadState::payload:
        if (!decryptor_.start_chunk(read_length_)) {
            forward_read();
            return;
        }
        forward_write();
    }
}

void Handler::TcpConnection::forward_parse_ipv4(size_t header_length) {
    address_v4::bytes_type address_bytes;
    memcpy(
        address_bytes.data(),
        decryptor_.pop_buffer(sizeof(address_bytes)),
        sizeof(address_bytes));
    uint16_t port = decryptor_.pop_big_u16();
    size_t initial_data_length = header_length - 7;
    const_buffer initial_data(
        decryptor_.pop_buffer(initial_data_length),
        initial_data_length);
    handler_.connector_.connect_tcp_v4(
        address_v4(address_bytes),
        port,
        initial_data,
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                return;
            }
            connection->decryptor_.finish_chunk();
            connection->read_state_ = ReadState::length;
            connection->remote_stream_ = std::move(stream);
            connection->forward_parse();
            connection->encryptor_.init(connection->handler_.pre_shared_key_);
            connection->backward_read();
        });
}

void Handler::TcpConnection::forward_parse_ipv6(size_t header_length) {
    address_v6::bytes_type address_bytes;
    memcpy(
        address_bytes.data(),
        decryptor_.pop_buffer(sizeof(address_bytes)),
        sizeof(address_bytes));
    uint16_t port = decryptor_.pop_big_u16();
    size_t initial_data_length = header_length - 19;
    const_buffer initial_data(
        decryptor_.pop_buffer(initial_data_length),
        initial_data_length);
    handler_.connector_.connect_tcp_v6(
        address_v6(address_bytes),
        port,
        initial_data,
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                return;
            }
            connection->decryptor_.finish_chunk();
            connection->read_state_ = ReadState::length;
            connection->remote_stream_ = std::move(stream);
            connection->forward_parse();
            connection->encryptor_.init(connection->handler_.pre_shared_key_);
            connection->backward_read();
        });
}

void Handler::TcpConnection::forward_parse_host(size_t header_length) {
    size_t host_length = decryptor_.pop_u8();
    if (2 + host_length + 2 > header_length) {
        return;
    }
    std::string_view host(
        reinterpret_cast<char *>(decryptor_.pop_buffer(host_length)),
        host_length);
    uint16_t port = decryptor_.pop_big_u16();
    size_t initial_data_length = header_length - (2 + host_length + 2);
    const_buffer initial_data(
        decryptor_.pop_buffer(initial_data_length),
        initial_data_length);
    handler_.connector_.connect_tcp_host(
        host,
        port,
        initial_data,
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                return;
            }
            connection->decryptor_.finish_chunk();
            connection->read_state_ = ReadState::length;
            connection->remote_stream_ = std::move(stream);
            connection->forward_parse();
            connection->encryptor_.init(connection->handler_.pre_shared_key_);
            connection->backward_read();
        });
}

void Handler::TcpConnection::forward_write() {
    async_write(
        *remote_stream_,
        buffer(decryptor_.pop_buffer(read_length_), read_length_),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                return;
            }
            connection->decryptor_.finish_chunk();
            connection->read_state_ = ReadState::length;
            connection->forward_parse();
        });
}

void Handler::TcpConnection::backward_read() {
    remote_stream_->async_read_some(
        buffer(backward_read_buffer_.data(), backward_read_buffer_.size()),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                return;
            }
            connection->backward_read_size_ = size;
            connection->backward_write();
        });
}

void Handler::TcpConnection::backward_write() {
    ConstBufferSpan read_buffer(
        backward_read_buffer_.data(), backward_read_size_);
    do {
        size_t chunk_size = std::min(
            read_buffer.size(),
            handler_.pre_shared_key_.method().max_chunk_size());
        encryptor_.write_length_chunk(chunk_size);
        encryptor_.write_payload_chunk(read_buffer.subspan(0, chunk_size));
        read_buffer.remove_prefix(chunk_size);
    } while (!read_buffer.empty());
    ConstBufferSpan write_buffer = encryptor_.buffer();
    async_write(
        stream_,
        buffer(write_buffer.data(), write_buffer.size()),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                return;
            }
            connection->encryptor_.clear();
            connection->backward_read();
        });
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
