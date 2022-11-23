#include "net/proxy/shadowsocks/connector.h"

#include "absl/base/attributes.h"
#include "net/proxy/shadowsocks/decryptor.h"
#include "net/proxy/shadowsocks/encryptor.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class Connector::TcpSocketStream : public proxy::Stream {
public:
    explicit TcpSocketStream(Connector &connector);

    void start(
        const net::address_v4 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(std::error_code) &&> callback);

    void start(
        const net::address_v6 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(std::error_code) &&> callback);

    void start(
        std::string_view host,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(std::error_code) &&> callback);

    void async_read_some(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void async_write_some(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    any_io_executor get_executor() override;

private:
    void connect(absl::AnyInvocable<void(std::error_code) &&> callback);

    void read(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback);

    enum class ReadState {
        init,
        length,
        payload,
        payload_tail,
    };

    Connector &connector_;
    std::unique_ptr<Stream> base_stream_;
    Encryptor encryptor_;
    Decryptor decryptor_;
    ReadState read_state_ = ReadState::init;
    uint16_t read_length_;
    ConstBufferSpan read_buffer_;
};

Connector::Connector(
    const any_io_executor &executor,
    proxy::Connector &base_connector)
    : executor_(executor),
      base_connector_(base_connector) {}

bool Connector::init(const Config &config) {
    endpoint_ = config.endpoint;
    return pre_shared_key_.init(*config.method, config.password);
}

void Connector::connect_tcp_v4(
    const address_v4 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    auto stream = std::make_unique<TcpSocketStream>(*this);
    stream->start(
        address,
        port,
        initial_data,
        [stream = std::move(stream), callback = std::move(callback)](
            std::error_code ec) mutable {
            if (ec) {
                std::move(callback)(ec, nullptr);
                return;
            }
            std::move(callback)({}, std::move(stream));
        });
}

void Connector::connect_tcp_v6(
    const address_v6 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    auto stream = std::make_unique<TcpSocketStream>(*this);
    stream->start(
        address,
        port,
        initial_data,
        [stream = std::move(stream), callback = std::move(callback)](
            std::error_code ec) mutable {
            if (ec) {
                std::move(callback)(ec, nullptr);
                return;
            }
            std::move(callback)({}, std::move(stream));
        });
}

void Connector::connect_tcp_host(
    std::string_view host,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    auto stream = std::make_unique<TcpSocketStream>(*this);
    stream->start(
        host,
        port,
        initial_data,
        [stream = std::move(stream), callback = std::move(callback)](
            std::error_code ec) mutable {
            if (ec) {
                std::move(callback)(ec, nullptr);
                return;
            }
            std::move(callback)({}, std::move(stream));
        });
}

std::error_code Connector::bind_udp_v4(std::unique_ptr<Datagram> &datagram) {
    // TODO
    return make_error_code(std::errc::operation_not_supported);
}

std::error_code Connector::bind_udp_v6(std::unique_ptr<Datagram> &datagram) {
    // TODO
    return make_error_code(std::errc::operation_not_supported);
}

Connector::TcpSocketStream::TcpSocketStream(Connector &connector)
    : connector_(connector) {}

void Connector::TcpSocketStream::start(
    const net::address_v4 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    encryptor_.init(connector_.pre_shared_key_);
    encryptor_.start_chunk();
    encryptor_.push_big_u16(7 + initial_data.size());
    encryptor_.finish_chunk();
    encryptor_.start_chunk();
    encryptor_.push_u8(1);  // ipv4
    encryptor_.push_buffer(address.to_bytes());
    encryptor_.push_big_u16(port);
    encryptor_.push_buffer({initial_data.data(), initial_data.size()});
    encryptor_.finish_chunk();
    connect(std::move(callback));
}

void Connector::TcpSocketStream::start(
    const net::address_v6 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    encryptor_.init(connector_.pre_shared_key_);
    encryptor_.start_chunk();
    encryptor_.push_big_u16(19 + initial_data.size());
    encryptor_.finish_chunk();
    encryptor_.start_chunk();
    encryptor_.push_u8(4);  // ipv6
    encryptor_.push_buffer(address.to_bytes());
    encryptor_.push_big_u16(port);
    encryptor_.push_buffer({initial_data.data(), initial_data.size()});
    encryptor_.finish_chunk();
    connect(std::move(callback));
}

void Connector::TcpSocketStream::start(
    std::string_view host,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    encryptor_.init(connector_.pre_shared_key_);
    encryptor_.start_chunk();
    encryptor_.push_big_u16(2 + host.size() + 2 + initial_data.size());
    encryptor_.finish_chunk();
    encryptor_.start_chunk();
    encryptor_.push_u8(3);  // host
    encryptor_.push_u8(host.size());
    encryptor_.push_buffer(host);
    encryptor_.push_big_u16(port);
    encryptor_.push_buffer({initial_data.data(), initial_data.size()});
    encryptor_.finish_chunk();
    connect(std::move(callback));
}

void Connector::TcpSocketStream::connect(
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    auto wrapped_callback = [this, callback = std::move(callback)](
        std::error_code ec, std::unique_ptr<Stream> stream) mutable {
        if (ec) {
            std::move(callback)(ec);
            return;
        }
        base_stream_ = std::move(stream);
        std::move(callback)({});
    };
    if (connector_.endpoint_.address().is_v4()) {
        connector_.base_connector_.connect_tcp_v4(
            connector_.endpoint_.address().to_v4(),
            connector_.endpoint_.port(),
            buffer(encryptor_.buffer().data(), encryptor_.buffer().size()),
            std::move(wrapped_callback));
    } else {
        connector_.base_connector_.connect_tcp_v6(
            connector_.endpoint_.address().to_v6(),
            connector_.endpoint_.port(),
            buffer(encryptor_.buffer().data(), encryptor_.buffer().size()),
            std::move(wrapped_callback));
    }
}

void Connector::TcpSocketStream::async_read_some(
    absl::Span<mutable_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    while (true) {
        switch (read_state_) {
        case ReadState::init:
            if (!decryptor_.init(connector_.pre_shared_key_)) {
                read(buffers, std::move(callback));
                return;
            }
            read_state_ = ReadState::length;
            ABSL_FALLTHROUGH_INTENDED;
        case ReadState::length:
            if (!decryptor_.start_chunk(2)) {
                read(buffers, std::move(callback));
                return;
            }
            read_length_ = decryptor_.pop_big_u16();
            decryptor_.finish_chunk();
            read_state_ = ReadState::payload;
            ABSL_FALLTHROUGH_INTENDED;
        case ReadState::payload:
            if (!decryptor_.start_chunk(read_length_)) {
                read(buffers, std::move(callback));
                return;
            }
            read_buffer_ = {decryptor_.pop_buffer(read_length_), read_length_};
            read_state_ = ReadState::payload_tail;
            ABSL_FALLTHROUGH_INTENDED;
        case ReadState::payload_tail:
            size_t total_size = 0;
            for (mutable_buffer buffer : buffers) {
                size_t size = std::min(buffer.size(), read_buffer_.size());
                memcpy(buffer.data(), read_buffer_.data(), size);
                read_buffer_.remove_prefix(size);
                total_size += size;
                if (read_buffer_.empty()) {
                    decryptor_.finish_chunk();
                    read_state_ = ReadState::length;
                    std::move(callback)({}, total_size);
                    return;
                }
                if (size < buffer.size()) {
                    std::move(callback)({}, total_size);
                    return;
                }
            }
            std::move(callback)({}, total_size);
            break;
        }
    }
}

void Connector::TcpSocketStream::read(
    absl::Span<mutable_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    absl::FixedArray<mutable_buffer, 1> buffers_copy(
        buffers.begin(), buffers.end());
    base_stream_->async_read_some(
        mutable_buffer(decryptor_.buffer().data(), decryptor_.buffer().size()),
        [this, buffers = std::move(buffers_copy),
            callback = std::move(callback)](
            std::error_code ec, size_t size) mutable {
            if (ec) {
                std::move(callback)(ec, 0);
                return;
            }
            decryptor_.advance(size);
            async_read_some(buffers, std::move(callback));
        });
}

void Connector::TcpSocketStream::async_write_some(
    absl::Span<const_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    size_t total_size = 0;
    encryptor_.clear();
    for (const_buffer buffer : buffers) {
        encryptor_.start_chunk();
        encryptor_.push_big_u16(buffer.size());
        encryptor_.finish_chunk();
        encryptor_.start_chunk();
        encryptor_.push_buffer({buffer.data(), buffer.size()});
        encryptor_.finish_chunk();
        total_size += buffer.size();
    }
    async_write(
        *base_stream_,
        buffer(encryptor_.buffer().data(), encryptor_.buffer().size()),
        [total_size, callback = std::move(callback)](
            std::error_code ec, size_t) mutable {
            if (ec) {
                std::move(callback)(ec, 0);
                return;
            }
            std::move(callback)({}, total_size);
        });
}

any_io_executor Connector::TcpSocketStream::get_executor() {
    return connector_.executor_;
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
