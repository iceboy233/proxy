#include "net/proxy/shadowsocks/connector.h"

#include <chrono>
#include <memory>
#include <utility>

#include "base/logging.h"
#include "net/proxy/shadowsocks/decryptor.h"
#include "net/proxy/shadowsocks/encryptor.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class Connector::TcpStream : public proxy::Stream {
public:
    explicit TcpStream(Connector &connector);

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

    void read(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void write(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    any_io_executor get_executor() override { return connector_.executor_; }
    void close() override { base_stream_->close(); }

private:
    void connect(absl::AnyInvocable<void(std::error_code) &&> callback);

    void read_internal(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback);

    enum class ReadState {
        init,
        header,
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

bool Connector::init(const InitOptions &options) {
    endpoints_ = options.endpoints;
    if (endpoints_.empty()) {
        return false;
    }
    endpoints_iter_ = endpoints_.begin();
    if (!pre_shared_key_.init(*options.method, options.password)) {
        return false;
    }
    min_padding_length_ = options.min_padding_length;
    max_padding_length_ = options.max_padding_length;
    return true;
}

void Connector::connect_tcp_v4(
    const address_v4 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    auto stream = std::make_unique<TcpStream>(*this);
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
    auto stream = std::make_unique<TcpStream>(*this);
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
    auto stream = std::make_unique<TcpStream>(*this);
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

Connector::TcpStream::TcpStream(Connector &connector)
    : connector_(connector) {}

void Connector::TcpStream::start(
    const net::address_v4 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    encryptor_.init(connector_.pre_shared_key_);
    connector_.salt_filter_.insert({
        encryptor_.salt(), connector_.pre_shared_key_.method().salt_size()});
    // TODO: split chunks if too large
    encryptor_.start_chunk();
    size_t padding_size = absl::Uniform<size_t>(
        connector_.bit_gen_,
        connector_.min_padding_length_,
        connector_.max_padding_length_);
    if (connector_.pre_shared_key_.method().is_spec_2022()) {
        encryptor_.push_u8(0);  // request
        encryptor_.push_big_u64(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        encryptor_.push_big_u16(padding_size + initial_data.size() + 9);
    } else {
        encryptor_.push_big_u16(initial_data.size() + 7);
    }
    encryptor_.finish_chunk();
    encryptor_.start_chunk();
    encryptor_.push_u8(1);  // ipv4
    encryptor_.push_buffer(address.to_bytes());
    encryptor_.push_big_u16(port);
    if (connector_.pre_shared_key_.method().is_spec_2022()) {
        encryptor_.push_big_u16(padding_size);
        encryptor_.push_random(padding_size);
    }
    encryptor_.push_buffer({initial_data.data(), initial_data.size()});
    encryptor_.finish_chunk();
    connect(std::move(callback));
}

void Connector::TcpStream::start(
    const net::address_v6 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    encryptor_.init(connector_.pre_shared_key_);
    connector_.salt_filter_.insert({
        encryptor_.salt(), connector_.pre_shared_key_.method().salt_size()});
    // TODO: split chunks if too large
    encryptor_.start_chunk();
    size_t padding_size = absl::Uniform<size_t>(
        connector_.bit_gen_,
        connector_.min_padding_length_,
        connector_.max_padding_length_);
    if (connector_.pre_shared_key_.method().is_spec_2022()) {
        encryptor_.push_u8(0);  // request
        encryptor_.push_big_u64(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        encryptor_.push_big_u16(padding_size + initial_data.size() + 21);
    } else {
        encryptor_.push_big_u16(initial_data.size() + 19);
    }
    encryptor_.finish_chunk();
    encryptor_.start_chunk();
    encryptor_.push_u8(4);  // ipv6
    encryptor_.push_buffer(address.to_bytes());
    encryptor_.push_big_u16(port);
    if (connector_.pre_shared_key_.method().is_spec_2022()) {
        encryptor_.push_big_u16(padding_size);
        encryptor_.push_random(padding_size);
    }
    encryptor_.push_buffer({initial_data.data(), initial_data.size()});
    encryptor_.finish_chunk();
    connect(std::move(callback));
}

void Connector::TcpStream::start(
    std::string_view host,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    encryptor_.init(connector_.pre_shared_key_);
    connector_.salt_filter_.insert({
        encryptor_.salt(), connector_.pre_shared_key_.method().salt_size()});
    // TODO: split chunks if too large
    encryptor_.start_chunk();
    size_t padding_size = absl::Uniform<size_t>(
        connector_.bit_gen_,
        connector_.min_padding_length_,
        connector_.max_padding_length_);
    if (connector_.pre_shared_key_.method().is_spec_2022()) {
        encryptor_.push_u8(0);  // request
        encryptor_.push_big_u64(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        encryptor_.push_big_u16(
            host.size() + padding_size + initial_data.size() + 6);
    } else {
        encryptor_.push_big_u16(host.size() + initial_data.size() + 4);
    }
    encryptor_.finish_chunk();
    encryptor_.start_chunk();
    encryptor_.push_u8(3);  // host
    encryptor_.push_u8(host.size());
    encryptor_.push_buffer(host);
    encryptor_.push_big_u16(port);
    if (connector_.pre_shared_key_.method().is_spec_2022()) {
        encryptor_.push_big_u16(padding_size);
        encryptor_.push_random(padding_size);
    }
    encryptor_.push_buffer({initial_data.data(), initial_data.size()});
    encryptor_.finish_chunk();
    connect(std::move(callback));
}

void Connector::TcpStream::connect(
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    ConstBufferSpan write_buffer = encryptor_.buffer();
    auto wrapped_callback = [this, callback = std::move(callback)](
        std::error_code ec, std::unique_ptr<Stream> stream) mutable {
        if (ec) {
            std::move(callback)(ec);
            return;
        }
        base_stream_ = std::move(stream);
        std::move(callback)({});
    };
    const Endpoint &endpoint = *connector_.endpoints_iter_++;
    if (connector_.endpoints_iter_ == connector_.endpoints_.end()) {
        connector_.endpoints_iter_ = connector_.endpoints_.begin();
    }
    if (endpoint.address().is_v4()) {
        connector_.base_connector_.connect_tcp_v4(
            endpoint.address().to_v4(),
            endpoint.port(),
            buffer(write_buffer.data(), write_buffer.size()),
            std::move(wrapped_callback));
    } else {
        connector_.base_connector_.connect_tcp_v6(
            endpoint.address().to_v6(),
            endpoint.port(),
            buffer(write_buffer.data(), write_buffer.size()),
            std::move(wrapped_callback));
    }
}

void Connector::TcpStream::read(
    absl::Span<mutable_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    while (true) {
        switch (read_state_) {
        case ReadState::init:
            if (!decryptor_.init(connector_.pre_shared_key_)) {
                read_internal(buffers, std::move(callback));
                return;
            }
            if (!connector_.pre_shared_key_.method().is_spec_2022()) {
                read_state_ = ReadState::length;
                continue;
            }
            read_state_ = ReadState::header;
            [[fallthrough]];
        case ReadState::header:
            if (!decryptor_.start_chunk(
                connector_.pre_shared_key_.method().salt_size() + 11)) {
                read_internal(buffers, std::move(callback));
                return;
            }
            if (!connector_.salt_filter_.test_and_insert({
                decryptor_.salt(),
                connector_.pre_shared_key_.method().salt_size()})) {
                LOG(warning) << "duplicated salt";
                decryptor_.discard();
                read_internal(buffers, std::move(callback));
                return;
            }
            if (decryptor_.pop_u8() != 1) {
                LOG(warning) << "unexpected header type";
                decryptor_.discard();
                read_internal(buffers, std::move(callback));
                return;
            }
            if (std::abs(static_cast<int64_t>(decryptor_.pop_big_u64()) -
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                            .count()) > 30) {
                LOG(warning) << "time difference too large";
                decryptor_.discard();
                read_internal(buffers, std::move(callback));
                return;
            }
            if (memcmp(
                encryptor_.salt(),
                decryptor_.pop_buffer(
                    connector_.pre_shared_key_.method().salt_size()),
                connector_.pre_shared_key_.method().salt_size())) {
                LOG(warning) << "salt mismatch";
                decryptor_.discard();
                read_internal(buffers, std::move(callback));
                return;
            }
            read_length_ = decryptor_.pop_big_u16();
            decryptor_.finish_chunk();
            read_state_ = ReadState::payload;
            continue;
        case ReadState::length:
            if (!decryptor_.start_chunk(2)) {
                read_internal(buffers, std::move(callback));
                return;
            }
            read_length_ = decryptor_.pop_big_u16();
            decryptor_.finish_chunk();
            read_state_ = ReadState::payload;
            [[fallthrough]];
        case ReadState::payload:
            if (!decryptor_.start_chunk(read_length_)) {
                read_internal(buffers, std::move(callback));
                return;
            }
            read_buffer_ = {decryptor_.pop_buffer(read_length_), read_length_};
            read_state_ = ReadState::payload_tail;
            [[fallthrough]];
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
        }
    }
}

void Connector::TcpStream::read_internal(
    absl::Span<mutable_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    absl::FixedArray<mutable_buffer, 1> buffers_copy(
        buffers.begin(), buffers.end());
    BufferSpan read_buffer = decryptor_.buffer();
    base_stream_->async_read_some(
        buffer(read_buffer.data(), read_buffer.size()),
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

void Connector::TcpStream::write(
    absl::Span<const_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    size_t total_size = 0;
    encryptor_.clear();
    for (const_buffer buffer : buffers) {
        // TODO: split chunks if too large
        encryptor_.start_chunk();
        encryptor_.push_big_u16(buffer.size());
        encryptor_.finish_chunk();
        encryptor_.write_payload_chunk({buffer.data(), buffer.size()});
        total_size += buffer.size();
    }
    ConstBufferSpan write_buffer = encryptor_.buffer();
    async_write(
        *base_stream_,
        buffer(write_buffer.data(), write_buffer.size()),
        [total_size, callback = std::move(callback)](
            std::error_code ec, size_t) mutable {
            if (ec) {
                std::move(callback)(ec, 0);
                return;
            }
            std::move(callback)({}, total_size);
        });
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
