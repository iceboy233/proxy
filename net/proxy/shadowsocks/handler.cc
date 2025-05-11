#include "net/proxy/shadowsocks/handler.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <utility>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include "absl/container/fixed_array.h"
#include "base/logging.h"
#include "net/proxy/shadowsocks/decryptor.h"
#include "net/proxy/shadowsocks/encryptor.h"
#include "net/proxy/util/write.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class Handler::TcpConnection : public boost::intrusive_ref_counter<
    TcpConnection, boost::thread_unsafe_counter> {
public:
    TcpConnection(Handler &handler, std::unique_ptr<Stream> stream);

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
    void close();

    enum class ReadState {
        init,
        header_length,
        header_payload,
        length,
        payload,
    };

    Handler &handler_;
    std::unique_ptr<Stream> stream_;
    std::unique_ptr<Stream> remote_stream_;
    Encryptor encryptor_;
    Decryptor decryptor_;
    ReadState read_state_ = ReadState::init;
    uint16_t read_length_;
    absl::FixedArray<uint8_t, 0> backward_read_buffer_;
    size_t backward_read_size_;
    bool write_header_;
};

bool Handler::init(const InitOptions &options) {
    return pre_shared_key_.init(*options.method, options.password);
}

void Handler::handle_stream(std::unique_ptr<Stream> stream) {
    boost::intrusive_ptr<TcpConnection> connection(new TcpConnection(
        *this, std::move(stream)));
    connection->start();
}

void Handler::handle_datagram(std::unique_ptr<Datagram> datagram) {
    // TODO: support datagram
    LOG(warning) << "datagram is not supported yet";
}

Handler::TcpConnection::TcpConnection(
    Handler &handler,
    std::unique_ptr<Stream> stream)
    : handler_(handler),
      stream_(std::move(stream)),
      // TODO: find out how to use larger buffer
      backward_read_buffer_(4096),
      write_header_(handler_.pre_shared_key_.method().is_spec_2022()) {}

void Handler::TcpConnection::forward_read() {
    BufferSpan read_buffer = decryptor_.buffer();
    stream_->read(
        {{read_buffer.data(), read_buffer.size()}},
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                connection->close();
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
        [[fallthrough]];
    case ReadState::header_length:
        if (handler_.pre_shared_key_.method().is_spec_2022()) {
            if (!decryptor_.start_chunk(11)) {
                forward_read();
                return;
            }
            if (decryptor_.pop_u8() != 0) {
                LOG(warning) << "unexpected header type";
                decryptor_.discard();
                forward_read();
                return;
            }
            if (std::abs(static_cast<int64_t>(decryptor_.pop_big_u64()) -
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                            .count()) > 30) {
                LOG(warning) << "time difference too large";
                decryptor_.discard();
                forward_read();
                return;
            }
        } else {
            if (!decryptor_.start_chunk(2)) {
                forward_read();
                return;
            }
        }
        if (!handler_.salt_filter_.test_and_insert({
            decryptor_.salt(),
            handler_.pre_shared_key_.method().salt_size()})) {
            LOG(warning) << "duplicated salt";
            decryptor_.discard();
            forward_read();
            return;
        }
        read_length_ = decryptor_.pop_big_u16();
        decryptor_.finish_chunk();
        read_state_ = ReadState::header_payload;
        [[fallthrough]];
    case ReadState::header_payload:
        if (!decryptor_.start_chunk(read_length_)) {
            forward_read();
            return;
        }
        switch (decryptor_.pop_u8()) {
        case 1:  // ipv4
            forward_parse_ipv4(read_length_);
            break;
        case 4:  // ipv6
            forward_parse_ipv6(read_length_);
            break;
        case 3:  // host
            forward_parse_host(read_length_);
            break;
        }
        return;
    case ReadState::length:
        if (!decryptor_.start_chunk(2)) {
            forward_read();
            return;
        }
        read_length_ = decryptor_.pop_big_u16();
        decryptor_.finish_chunk();
        read_state_ = ReadState::payload;
        [[fallthrough]];
    case ReadState::payload:
        if (!decryptor_.start_chunk(read_length_)) {
            forward_read();
            return;
        }
        forward_write();
    }
}

void Handler::TcpConnection::forward_parse_ipv4(size_t header_length) {
    if (header_length < 7) {
        return;
    }
    address_v4::bytes_type address_bytes;
    memcpy(
        address_bytes.data(),
        decryptor_.pop_buffer(sizeof(address_bytes)),
        sizeof(address_bytes));
    uint16_t port = decryptor_.pop_big_u16();
    size_t initial_data_length;
    if (handler_.pre_shared_key_.method().is_spec_2022()) {
        if (header_length < 9) {
            return;
        }
        size_t padding_length = decryptor_.pop_big_u16();
        if (header_length < 9 + padding_length) {
            return;
        }
        decryptor_.pop_buffer(padding_length);
        initial_data_length = header_length - (9 + padding_length);
        if (!padding_length && !initial_data_length) {
            return;
        }
    } else {
        initial_data_length = header_length - 7;
    }
    const_buffer initial_data(
        decryptor_.pop_buffer(initial_data_length),
        initial_data_length);
    handler_.connector_.connect(
        {address_v4(address_bytes), port},
        initial_data,
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                connection->close();
                return;
            }
            connection->decryptor_.finish_chunk();
            connection->read_state_ = ReadState::length;
            connection->remote_stream_ = std::move(stream);
            connection->forward_parse();
            connection->encryptor_.init(connection->handler_.pre_shared_key_);
            connection->handler_.salt_filter_.insert({
                connection->encryptor_.salt(),
                connection->handler_.pre_shared_key_.method().salt_size()});
            connection->backward_read();
        });
}

void Handler::TcpConnection::forward_parse_ipv6(size_t header_length) {
    if (header_length < 19) {
        return;
    }
    address_v6::bytes_type address_bytes;
    memcpy(
        address_bytes.data(),
        decryptor_.pop_buffer(sizeof(address_bytes)),
        sizeof(address_bytes));
    uint16_t port = decryptor_.pop_big_u16();
    size_t initial_data_length;
    if (handler_.pre_shared_key_.method().is_spec_2022()) {
        if (header_length < 21) {
            return;
        }
        size_t padding_length = decryptor_.pop_big_u16();
        if (header_length < 21 + padding_length) {
            return;
        }
        decryptor_.pop_buffer(padding_length);
        initial_data_length = header_length - (21 + padding_length);
        if (!padding_length && !initial_data_length) {
            return;
        }
    } else {
        initial_data_length = header_length - 19;
    }
    const_buffer initial_data(
        decryptor_.pop_buffer(initial_data_length),
        initial_data_length);
    handler_.connector_.connect(
        {address_v6(address_bytes), port},
        initial_data,
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                connection->close();
                return;
            }
            connection->decryptor_.finish_chunk();
            connection->read_state_ = ReadState::length;
            connection->remote_stream_ = std::move(stream);
            connection->forward_parse();
            connection->encryptor_.init(connection->handler_.pre_shared_key_);
            connection->handler_.salt_filter_.insert({
                connection->encryptor_.salt(),
                connection->handler_.pre_shared_key_.method().salt_size()});
            connection->backward_read();
        });
}

void Handler::TcpConnection::forward_parse_host(size_t header_length) {
    size_t host_length = decryptor_.pop_u8();
    if (header_length < host_length + 4) {
        return;
    }
    std::string_view host(
        reinterpret_cast<char *>(decryptor_.pop_buffer(host_length)),
        host_length);
    uint16_t port = decryptor_.pop_big_u16();
    size_t initial_data_length;
    if (handler_.pre_shared_key_.method().is_spec_2022()) {
        if (header_length < host_length + 6) {
            return;
        }
        size_t padding_length = decryptor_.pop_big_u16();
        if (header_length < host_length + padding_length + 6) {
            return;
        }
        decryptor_.pop_buffer(padding_length);
        initial_data_length =
            header_length - (host_length + padding_length + 6);
        if (!padding_length && !initial_data_length) {
            return;
        }
    } else {
        initial_data_length = header_length - (host_length + 4);
    }
    const_buffer initial_data(
        decryptor_.pop_buffer(initial_data_length),
        initial_data_length);
    handler_.connector_.connect(
        {host, port},
        initial_data,
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                connection->close();
                return;
            }
            connection->decryptor_.finish_chunk();
            connection->read_state_ = ReadState::length;
            connection->remote_stream_ = std::move(stream);
            connection->forward_parse();
            connection->encryptor_.init(connection->handler_.pre_shared_key_);
            connection->handler_.salt_filter_.insert({
                connection->encryptor_.salt(),
                connection->handler_.pre_shared_key_.method().salt_size()});
            connection->backward_read();
        });
}

void Handler::TcpConnection::forward_write() {
    write(
        *remote_stream_,
        {decryptor_.pop_buffer(read_length_), read_length_},
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec) {
            if (ec) {
                connection->close();
                return;
            }
            connection->decryptor_.finish_chunk();
            connection->read_state_ = ReadState::length;
            connection->forward_parse();
        });
}

void Handler::TcpConnection::backward_read() {
    remote_stream_->read(
        {{backward_read_buffer_.data(), backward_read_buffer_.size()}},
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                connection->close();
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
        encryptor_.start_chunk();
        if (write_header_) {
            encryptor_.push_u8(1);  // response
            encryptor_.push_big_u64(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                        .count());
            encryptor_.push_buffer({
                decryptor_.salt(),
                handler_.pre_shared_key_.method().salt_size()});
            write_header_ = false;
        }
        size_t chunk_size = std::min(
            read_buffer.size(),
            handler_.pre_shared_key_.method().max_chunk_size());
        encryptor_.push_big_u16(chunk_size);
        encryptor_.finish_chunk();
        encryptor_.write_payload_chunk(read_buffer.subspan(0, chunk_size));
        read_buffer.remove_prefix(chunk_size);
    } while (!read_buffer.empty());
    write(
        *stream_,
        encryptor_.buffer(),
        [connection = boost::intrusive_ptr<TcpConnection>(this)](
            std::error_code ec) {
            if (ec) {
                connection->close();
                return;
            }
            connection->encryptor_.clear();
            connection->backward_read();
        });
}

void Handler::TcpConnection::close() {
    if (remote_stream_) {
        remote_stream_->close();
    }
    stream_->close();
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
