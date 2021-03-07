#include "net/shadowsocks/udp-server.h"

#include <cstddef>
#include <cstdint>
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

class UdpServer::Connection : public boost::intrusive_ref_counter<
    Connection, boost::thread_unsafe_counter> {
public:
    Connection(
        UdpServer &server, const udp::endpoint &client_endpoint, 
        absl::Span<const uint8_t> first_chunk);
    ~Connection();

    void forward_parse(absl::Span<const uint8_t> chunk);

private:
    void forward_send(
        absl::Span<const uint8_t> chunk, const udp::endpoint &endpoint);
    void backward_receive();
    void backward_send(size_t payload_size);
    void wait();
    void close();

    UdpServer &server_;
    udp::socket remote_socket_;
    steady_timer timer_;
    udp::endpoint client_endpoint_;
    udp::endpoint remote_endpoint_;
    std::unique_ptr<uint8_t[]> backward_buffer_;
    static constexpr size_t backward_buffer_size_ = 65535 - 48;
    static constexpr size_t reserve_header_size_ = 19;
};


UdpServer::UdpServer(
    const any_io_executor &executor,
    const udp::endpoint &endpoint,
    const MasterKey &master_key,
    SaltFilter &salt_filter,
    const Options &options)
    : executor_(executor),
      master_key_(master_key),
      salt_filter_(salt_filter),
      options_(options),
      socket_(executor, endpoint),
      encrypted_datagram_(socket_, master_key, salt_filter) {
    receive();
}

void UdpServer::receive() {
    encrypted_datagram_.receive_from(
        [this] (
            std::error_code ec, absl::Span<const uint8_t> chunk,
            const udp::endpoint &endpoint) {
            if (ec) {
                receive();
                return;
            }
            forward_dispatch(chunk, endpoint);
        });
}

void UdpServer::send(
    absl::Span<const uint8_t> chunk, const udp::endpoint &endpoint,
    std::function<void(std::error_code)> callback) {
    encrypted_datagram_.send_to(chunk, endpoint,
        [callback = std::move(callback)] (std::error_code ec) {
            callback(ec);
        });
}

void UdpServer::forward_dispatch(
    absl::Span<const uint8_t> chunk, const udp::endpoint &client_endpoint) {
    auto iter = client_endpoints_.find(client_endpoint);
    if (iter != client_endpoints_.end()) {
        iter->second->forward_parse(chunk);
    } else {
        boost::intrusive_ptr<Connection> connection(
            new Connection(*this, client_endpoint, chunk));
    }
}

UdpServer::Connection::Connection(
    UdpServer &server, const udp::endpoint &client_endpoint, 
    absl::Span<const uint8_t> first_chunk)
    : server_(server),
      remote_socket_(server_.executor_),
      timer_(server_.executor_),
      client_endpoint_(client_endpoint),
      backward_buffer_(std::make_unique<uint8_t[]>(backward_buffer_size_)) {
    server_.client_endpoints_.emplace(client_endpoint_, this);
    forward_parse(first_chunk);
    backward_receive();
}

UdpServer::Connection::~Connection() {
    server_.client_endpoints_.erase(client_endpoint_);
}

void UdpServer::Connection::forward_parse(absl::Span<const uint8_t> chunk) {
    // Parse address, assuming the whole address is in the first chunk.
    wait();
    if (chunk.size() < 1) {
        server_.receive();
        return;
    }
    const auto *header =
        reinterpret_cast<const wire::AddressHeader *>(chunk.data());
    switch (header->type) {
    case wire::AddressType::ipv4:
        if (chunk.size() < 7) {
            server_.receive();
            return;
        }
        if (!remote_socket_.is_open())
            remote_socket_.open(udp::v4());
        forward_send(
            chunk.subspan(7), udp::endpoint(
                address_v4(header->ipv4_address),
                (chunk[5]) << 8 | chunk[6]));
        break;
    // TODO: support wire::AddressType::host
    case wire::AddressType::ipv6:
        if (chunk.size() < 19) {
            server_.receive();
            return;
        }
        if (!remote_socket_.is_open())
            remote_socket_.open(udp::v6());
        forward_send(
            chunk.subspan(19), udp::endpoint(
                address_v6(header->ipv6_address),
                (chunk[17]) << 8 | chunk[18]));
        break;
    default:
        server_.receive();
        return;
    }
}

void UdpServer::Connection::forward_send(
    absl::Span<const uint8_t> chunk, const udp::endpoint &endpoint) {
    remote_socket_.async_send_to(
        buffer(chunk.data(), chunk.size()), endpoint,
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t) {
            connection->server_.receive();
        });
}

void UdpServer::Connection::backward_receive() {
    remote_socket_.async_receive_from(
        buffer(backward_buffer_.get() + reserve_header_size_, 
            backward_buffer_size_ - reserve_header_size_), 
        remote_endpoint_,
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                connection->close();
                return;
            }
            connection->wait();
            connection->backward_send(size);
        });
}

void UdpServer::Connection::backward_send(size_t payload_size) {
    wire::AddressHeader *header;
    boost::endian::big_uint16_buf_t *port 
        = reinterpret_cast<boost::endian::big_uint16_buf_t *>(
            backward_buffer_.get() + reserve_header_size_ - 2);
    if (remote_endpoint_.address().is_v4()) {
        header = reinterpret_cast<wire::AddressHeader *>(
            backward_buffer_.get() + reserve_header_size_ - 7);
        payload_size += 7;
        header->type = wire::AddressType::ipv4;
        header->ipv4_address = remote_endpoint_.address().to_v4().to_bytes();
    } else {
        header = reinterpret_cast<wire::AddressHeader *>(
            backward_buffer_.get() + reserve_header_size_ - 19);
        payload_size += 19;
        header->type = wire::AddressType::ipv4;
        header->ipv6_address = remote_endpoint_.address().to_v6().to_bytes();
    }
    *port = remote_endpoint_.port();
    server_.send(
        {(uint8_t *)header, payload_size}, client_endpoint_, 
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec) {
            if (ec) {
                connection->close();
                return;
            }
            connection->backward_receive();
        });
}

void UdpServer::Connection::wait() {
    if (server_.options_.connection_timeout ==
        std::chrono::nanoseconds::zero()) {
        return;
    }
    timer_.expires_after(server_.options_.connection_timeout);
    timer_.async_wait(
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec) {
            if (ec) {
                return;
            }
            connection->close();
        });
}


void UdpServer::Connection::close() {
    remote_socket_.close();
    timer_.cancel();
}

}  // namespace shadowsocks
}  // namespace net
