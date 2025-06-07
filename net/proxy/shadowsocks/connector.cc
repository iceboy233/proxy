#include "net/proxy/shadowsocks/connector.h"

#include <chrono>
#include <limits>
#include <memory>
#include <utility>

#include "base/logging.h"
#include "net/interface/stream.h"
#include "net/proxy/shadowsocks/decryptor.h"
#include "net/proxy/shadowsocks/encryptor.h"
#include "net/proxy/util/write.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class Connector::TcpStream : public net::Stream {
public:
    explicit TcpStream(Connector &connector);

    void start(
        const HostPort &target,
        const_buffer initial_data,
        absl::AnyInvocable<void(std::error_code) &&> callback);

    void read(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void write(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

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

bool Connector::init(const InitOptions &options) {
    servers_ = options.servers;
    if (servers_.empty()) {
        return false;
    }
    servers_iter_ = servers_.begin();
    if (!pre_shared_key_.init(*options.method, options.password)) {
        return false;
    }
    min_padding_length_ = options.min_padding_length;
    max_padding_length_ = options.max_padding_length;
    return true;
}

void Connector::connect(
    const HostPort &target,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    auto stream = std::make_unique<TcpStream>(*this);
    stream->start(
        target,
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

std::error_code Connector::bind(
    const udp::endpoint &endpoint,
    std::unique_ptr<Datagram> &datagram) {
    // TODO
    return make_error_code(std::errc::operation_not_supported);
}

Connector::TcpStream::TcpStream(Connector &connector)
    : connector_(connector) {}

void Connector::TcpStream::start(
    const HostPort &target,
    const_buffer initial_data,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    encryptor_.init(connector_.pre_shared_key_);
    connector_.salt_filter_.insert({
        encryptor_.salt(), connector_.pre_shared_key_.method().salt_size()});

    // Request fixed-length header.
    encryptor_.start_chunk();
    size_t header_size;
    if (target.is_name_port()) {
        header_size = 4 + target.name().size();
    } else if (target.address().is_v4()) {
        header_size = 7;
    } else {
        header_size = 19;
    }
    size_t padding_size;
    if (connector_.pre_shared_key_.method().is_spec_2022()) {
        encryptor_.push_u8(0);  // request
        encryptor_.push_big_u64(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        padding_size = absl::Uniform<size_t>(
            connector_.bit_gen_,
            connector_.min_padding_length_,
            connector_.max_padding_length_);
        header_size += 2 + padding_size;
    }
    header_size += initial_data.size();
    if (header_size > std::numeric_limits<uint16_t>::max()) {
        std::move(callback)(make_error_code(std::errc::message_size));
        return;
    }
    encryptor_.push_big_u16(header_size);
    encryptor_.finish_chunk();

    // Request variable-length header.
    encryptor_.start_chunk();
    if (target.is_name_port()) {
        encryptor_.push_u8(3);  // host
        if (target.name().size() > std::numeric_limits<uint8_t>::max()) {
            std::move(callback)(make_error_code(std::errc::invalid_argument));
            return;
        }
        encryptor_.push_u8(target.name().size());
        encryptor_.push_buffer(target.name());
    } else if (target.address().is_v4()) {
        encryptor_.push_u8(1);  // ipv4
        encryptor_.push_buffer(target.address().to_v4().to_bytes());
    } else {
        encryptor_.push_u8(4);  // ipv6
        encryptor_.push_buffer(target.address().to_v6().to_bytes());
    }
    encryptor_.push_big_u16(target.port());
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
    const AddrPort &server = *connector_.servers_iter_++;
    if (connector_.servers_iter_ == connector_.servers_.end()) {
        connector_.servers_iter_ = connector_.servers_.begin();
    }
    ConstBufferSpan write_buffer = encryptor_.buffer();
    connector_.base_connector_.connect(
        server,
        {write_buffer.data(), write_buffer.size()},
        [this, callback = std::move(callback)](
            std::error_code ec, std::unique_ptr<Stream> stream) mutable {
            if (ec) {
                std::move(callback)(ec);
                return;
            }
            base_stream_ = std::move(stream);
            std::move(callback)({});
        });
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
    base_stream_->read(
        {{read_buffer.data(), read_buffer.size()}},
        [this, buffers = std::move(buffers_copy),
            callback = std::move(callback)](
            std::error_code ec, size_t size) mutable {
            if (ec) {
                std::move(callback)(ec, 0);
                return;
            }
            decryptor_.advance(size);
            read(buffers, std::move(callback));
        });
}

void Connector::TcpStream::write(
    absl::Span<const_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    size_t total_size = 0;
    encryptor_.clear();
    for (const_buffer buffer : buffers) {
        ConstBufferSpan buffer_span(buffer.data(), buffer.size());
        while (!buffer_span.empty()) {
            size_t chunk_size = std::min(
                buffer_span.size(),
                connector_.pre_shared_key_.method().max_chunk_size());
            encryptor_.start_chunk();
            encryptor_.push_big_u16(chunk_size);
            encryptor_.finish_chunk();
            encryptor_.write_payload_chunk(buffer_span.subspan(0, chunk_size));
            buffer_span.remove_prefix(chunk_size);
        }
        total_size += buffer.size();
    }
    proxy::write(
        *base_stream_,
        encryptor_.buffer(),
        [total_size, callback = std::move(callback)](
            std::error_code ec) mutable {
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
