#include "net/proxy/system/connector.h"

#include <array>
#include <utility>

#include "absl/strings/str_cat.h"
#include "base/logging.h"
#include "net/proxy/util/write.h"

namespace net {
namespace proxy {
namespace system {

class Connector::ConnectOperation {
public:
    ConnectOperation(
        Connector &connector,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback);

    void connect(const address &address, uint16_t port);
    void resolve(std::string_view host, uint16_t port);

private:
    void connect_next();
    void send_initial_data(std::unique_ptr<Stream> stream);
    void finish(std::error_code ec, std::unique_ptr<Stream> stream);

    Connector &connector_;
    const_buffer initial_data_;
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback_;
    std::vector<address> addresses_;
    uint16_t port_;
    std::vector<address>::iterator addresses_iter_;
};

Connector::Connector(const any_io_executor &executor, const Options &options)
    : executor_(executor),
      resolver_(executor_, *this, options.resolver_options),
      timer_list_(executor_, options.timeout),
      tcp_no_delay_(options.tcp_no_delay),
      tcp_fast_open_connect_(options.tcp_fast_open_connect) {}

void Connector::connect(
    const HostPort &target,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    auto *operation = new ConnectOperation(
        *this, initial_data, std::move(callback));
    if (target.is_name_port()) {
        operation->resolve(target.name(), target.port());
    } else {
        operation->connect(target.address(), target.port());
    }
}

std::error_code Connector::bind(
    const udp::endpoint &endpoint, std::unique_ptr<Datagram> &datagram) {
    udp::socket socket(executor_);
    boost::system::error_code ec;
    socket.open(endpoint.protocol(), ec);
    if (ec) {
        return ec;
    }
    socket.bind(endpoint, ec);
    if (ec) {
        return ec;
    }
    datagram = std::make_unique<UdpSocketDatagram>(std::move(socket));
    return {};
}

Connector::ConnectOperation::ConnectOperation(
    Connector &connector,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback)
    : connector_(connector),
      initial_data_(initial_data),
      callback_(std::move(callback)) {}

void Connector::ConnectOperation::connect(
    const address &address, uint16_t port) {
    addresses_ = {address};
    port_ = port;
    addresses_iter_ = addresses_.begin();
    connect_next();
}

void Connector::ConnectOperation::resolve(
    std::string_view host, uint16_t port) {
    port_ = port;
    connector_.resolver_.resolve(
        host,
        [this](
            std::error_code ec, const std::vector<address> &addresses) mutable {
        if (ec) {
            finish(ec, nullptr);
            return;
        }
        if (addresses.empty()) {
            finish(make_error_code(std::errc::host_unreachable), nullptr);
            return;
        }
        addresses_ = addresses;
        addresses_iter_ = addresses_.begin();
        connect_next();
    });
}

void Connector::ConnectOperation::connect_next() {
    auto stream = std::make_unique<TcpSocketStream>(
        tcp::socket(connector_.executor_), connector_.timer_list_);
    tcp::socket &socket = stream->socket();
    boost::system::error_code ec;
    socket.open(addresses_iter_->is_v4() ? tcp::v4() : tcp::v6(), ec);
    if (ec) {
        if (++addresses_iter_ == addresses_.end()) {
            finish(ec, nullptr);
        } else {
            connect_next();
        }
        return;
    }
    if (connector_.tcp_no_delay_) {
        socket.set_option(tcp::no_delay(true), ec);
        if (ec) {
            LOG(error) << "set_option failed for no_delay: " << ec;
        }
    }
#ifdef TCP_FASTOPEN_CONNECT
    switch (connector_.tcp_fast_open_connect_) {
    case 1:
        if (!initial_data_.size()) {
            break;
        }
        [[fallthrough]];
    case 2:
        socket.set_option(
            boost::asio::detail::socket_option::boolean<
                IPPROTO_TCP, TCP_FASTOPEN_CONNECT>(true), ec);
        if (ec) {
            LOG(error) << "set_option failed for fast_open_connect: " << ec;
        }
    }
#endif
    socket.async_connect(
        tcp::endpoint(*addresses_iter_, port_),
        [this, stream = std::move(stream)](std::error_code ec) mutable {
            if (ec) {
                if (++addresses_iter_ == addresses_.end()) {
                    finish(ec, nullptr);
                } else {
                    connect_next();
                }
                return;
            }
            if (initial_data_.size()) {
                send_initial_data(std::move(stream));
                return;
            }
            finish({}, std::move(stream));
        });
}

void Connector::ConnectOperation::send_initial_data(
    std::unique_ptr<Stream> stream) {
    Stream &stream_ref = *stream;
    write(
        stream_ref,
        {initial_data_.data(), initial_data_.size()},
        [this, stream = std::move(stream)](std::error_code ec) mutable {
        if (ec) {
            finish(ec, nullptr);
            return;
        }
        finish({}, std::move(stream));
    });
}

void Connector::ConnectOperation::finish(
    std::error_code ec, std::unique_ptr<Stream> stream) {
    std::move(callback_)(ec, std::move(stream));
    delete this;
}

}  // namespace system
}  // namespace proxy
}  // namespace net
