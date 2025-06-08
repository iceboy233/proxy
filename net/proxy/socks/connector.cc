#include "net/proxy/socks/connector.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <boost/endian/conversion.hpp>

#include "absl/base/optimization.h"
#include "base/logging.h"
#include "net/proxy/util/write.h"

namespace net {
namespace proxy {
namespace socks {

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

    void close() override;

private:
    enum class State {
        method_selection,
        request,
    };

    void dispatch();
    void read();
    void method_selection();
    void request();

    Connector &connector_;
    HostPort target_;
    const_buffer initial_data_;
    absl::AnyInvocable<void(std::error_code) &&> start_callback_;
    std::unique_ptr<Stream> stream_;
    size_t read_size_ = 0;
    State state_ = State::method_selection;
    std::array<uint8_t, 512> read_buffer_;
    std::array<uint8_t, 512> write_buffer_;
};

void Connector::connect(
    const HostPort &target,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    auto stream = std::make_unique<TcpStream>(*this);
    auto *stream_ptr = stream.get();
    stream_ptr->start(
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
    if (target.is_name_port() && target.name().size() > 255) {
        std::move(callback)(make_error_code(std::errc::invalid_argument));
        return;
    }
    target_ = target;
    initial_data_ = initial_data;
    start_callback_ = std::move(callback);
    write_buffer_[0] = 5;
    write_buffer_[1] = 1;
    write_buffer_[2] = 0;
    connector_.connector_.connect(
        connector_.server_,
        {&write_buffer_[0], 3},
        [this](std::error_code ec, std::unique_ptr<Stream> stream) {
            if (ec) {
                std::move(start_callback_)(ec);
                return;
            }
            stream_ = std::move(stream);
            read();
        });
}

void Connector::TcpStream::dispatch() {
    switch (state_) {
    case State::method_selection:
        method_selection();
        break;
    case State::request:
        request();
        break;
    }
}

void Connector::TcpStream::read() {
    stream_->read(
        {{&read_buffer_[read_size_], read_buffer_.size() - read_size_}},
        [this](std::error_code ec, size_t size) {
            if (ec) {
                std::move(start_callback_)(ec);
                return;
            }
            read_size_ += size;
            dispatch();
        });
}

void Connector::TcpStream::method_selection() {
    if (read_size_ < 2) {
        read();
        return;
    }
    if (read_buffer_[0] != 5) {
        std::move(start_callback_)(make_error_code(std::errc::protocol_error));
        return;
    }
    if (read_buffer_[1] != 0) {
        std::move(start_callback_)(
            make_error_code(std::errc::protocol_not_supported));
        return;
    }
    read_size_ = 0;
    write_buffer_[0] = 5;
    write_buffer_[1] = 1;
    write_buffer_[2] = 0;
    size_t addr_size;
    if (target_.is_name_port()) {
        write_buffer_[3] = 3;
        write_buffer_[4] = static_cast<uint8_t>(target_.name().size());
        memcpy(&write_buffer_[5], target_.name().data(), target_.name().size());
        addr_size = target_.name().size() + 1;
    } else if (target_.address().is_v4()) {
        write_buffer_[3] = 1;
        auto address_bytes = target_.address().to_v4().to_bytes();
        memcpy(&write_buffer_[4], address_bytes.data(), address_bytes.size());
        addr_size = address_bytes.size();
    } else {
        write_buffer_[3] = 4;
        auto address_bytes = target_.address().to_v6().to_bytes();
        memcpy(&write_buffer_[4], address_bytes.data(), address_bytes.size());
        addr_size = address_bytes.size();
    }
    boost::endian::store_big_u16(&write_buffer_[4 + addr_size], target_.port());
    state_ = State::request;
    proxy::write(
        *stream_,
        {&write_buffer_[0], addr_size + 6},
        [this](std::error_code ec) {
            if (ec) {
                std::move(start_callback_)(ec);
                return;
            }
            read();
        });

}

void Connector::TcpStream::request() {
    if (read_size_ < 4) {
        read();
        return;
    }
    if (read_buffer_[0] != 5) {
        std::move(start_callback_)(make_error_code(std::errc::protocol_error));
        return;
    }
    static const std::array<std::errc, 8> error_codes = {{
        std::errc::io_error,
        std::errc::permission_denied,
        std::errc::network_unreachable,
        std::errc::host_unreachable,
        std::errc::connection_refused,
        std::errc::timed_out,
        std::errc::operation_not_supported,
        std::errc::address_family_not_supported,
    }};
    if (read_buffer_[1] != 0) {
        std::errc error_code;
        if (static_cast<size_t>(read_buffer_[1] - 1) < error_codes.size()) {
            error_code = error_codes[read_buffer_[1] - 1];
        } else {
            error_code = std::errc::protocol_error;
        }
        std::move(start_callback_)(make_error_code(error_code));
        return;
    }
    switch (read_buffer_[3]) {
    case 1:
        if (read_size_ < 10) {
            read();
            return;
        }
        read_size_ -= 10;
        break;
    case 3:
        if (read_size_ < 5 ||
            read_size_ < static_cast<size_t>(read_buffer_[5] + 7)) {
            read();
            return;
        }
        read_size_ -= read_buffer_[5] + 7;
        break;
    case 4:
        if (read_size_ < 22) {
            read();
            return;
        }
        read_size_ -= 22;
        break;
    default:
        std::move(start_callback_)(
            make_error_code(std::errc::address_family_not_supported));
        return;
    }
    std::move(start_callback_)({});
}

void Connector::TcpStream::read(
    absl::Span<mutable_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    if (ABSL_PREDICT_FALSE(read_size_)) {
        size_t size = 0;
        for (mutable_buffer buffer : buffers) {
            size_t copy_size = std::min(read_size_, buffer.size());
            memcpy(buffer.data(), &read_buffer_[size], copy_size);
            size += copy_size;
            read_size_ -= copy_size;
        }
        memmove(&read_buffer_[0], &read_buffer_[size], read_size_);
        std::move(callback)({}, size);
        return;
    }
    stream_->read(buffers, std::move(callback));
}

void Connector::TcpStream::write(
    absl::Span<const_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    stream_->write(buffers, std::move(callback));
}

void Connector::TcpStream::close() {
    stream_->close();
}

}  // namespace socks
}  // namespace proxy
}  // namespace net
