#include "net/shadowsocks/udp-server.h"

#include <cstddef>
#include <memory>
#include <string_view>
#include <system_error>

#include "absl/strings/str_cat.h"
#include "base/logging.h"
#include "boost/endian/conversion.hpp"
#include "boost/smart_ptr/intrusive_ptr.hpp"
#include "boost/smart_ptr/intrusive_ref_counter.hpp"
#include "net/shadowsocks/wire-structs.h"

namespace net {
namespace shadowsocks {

class UdpServer::Connection : public boost::intrusive_ref_counter<
    Connection, boost::thread_unsafe_counter> {
public:
    Connection(
        UdpServer &server,
        const udp::endpoint &client_endpoint,
        bool is_v6);
    ~Connection();

    void forward_send(
        absl::Span<const uint8_t> chunk, const udp::endpoint &endpoint);
    void backward_receive();
    void wait();

private:
    void backward_send();
    void close();

    UdpServer &server_;
    udp::endpoint client_endpoint_;
    bool is_v6_;
    udp::socket remote_socket_;
    steady_timer timer_;
    std::unique_ptr<uint8_t[]> backward_buffer_;
    static constexpr size_t backward_buffer_size_ = 65535 - 48;
    udp::endpoint backward_receive_endpoint_;
    size_t backward_receive_size_;
    static constexpr size_t reserve_header_size_ = 19;
};

UdpServer::UdpServer(
    const any_io_executor &executor,
    const udp::endpoint &endpoint,
    const MasterKey &master_key,
    const Options &options)
    : executor_(executor),
      options_(options),
      socket_(executor, endpoint),
      encrypted_datagram_(socket_, master_key, options_.salt_filter) {
    forward_receive();
}

void UdpServer::forward_receive() {
    encrypted_datagram_.receive_from(
        receive_endpoint_,
        [this](std::error_code ec, absl::Span<const uint8_t> chunk) {
            if (ec) {
                forward_receive();
                return;
            }
            forward_parse(chunk);
        });
}

void UdpServer::forward_parse(absl::Span<const uint8_t> chunk) {
    // Parse address, assuming the whole address is in the first chunk.
    if (chunk.size() < 1) {
        forward_receive();
        return;
    }
    const auto *header =
        reinterpret_cast<const wire::AddressHeader *>(chunk.data());
    switch (header->type) {
    case wire::AddressType::ipv4:
        if (chunk.size() < 7) {
            forward_receive();
            return;
        }
        forward_dispatch(
            chunk.subspan(7),
            udp::endpoint(
                address_v4(header->ipv4_address),
                boost::endian::load_big_u16(&chunk[5])));
        break;
    // TODO: support wire::AddressType::host
    case wire::AddressType::ipv6:
        if (chunk.size() < 19) {
            forward_receive();
            return;
        }
        forward_dispatch(
            chunk.subspan(19),
            udp::endpoint(
                address_v6(header->ipv6_address),
                boost::endian::load_big_u16(&chunk[17])));
        break;
    default:
        forward_receive();
        return;
    }
}

void UdpServer::forward_dispatch(
    absl::Span<const uint8_t> chunk,
    const udp::endpoint &server_endpoint) {
    auto iter = connections_.find(
        {receive_endpoint_, server_endpoint.address().is_v6()});
    if (iter != connections_.end()) {
        iter->second->forward_send(chunk, server_endpoint);
    } else {
        boost::intrusive_ptr<Connection> connection(new Connection(
            *this, receive_endpoint_, server_endpoint.address().is_v6()));
        connection->forward_send(chunk, server_endpoint);
        connection->backward_receive();
        connection->wait();
    }
}

UdpServer::Connection::Connection(
    UdpServer &server,
    const udp::endpoint &client_endpoint,
    bool is_v6)
    : server_(server),
      client_endpoint_(client_endpoint),
      is_v6_(is_v6),
      remote_socket_(server_.executor_, {!is_v6_ ? udp::v4() : udp::v6(), 0}),
      timer_(server_.executor_),
      backward_buffer_(std::make_unique<uint8_t[]>(backward_buffer_size_)) {
    server_.connections_.emplace(
        std::make_tuple(client_endpoint_, is_v6_), this);
}

UdpServer::Connection::~Connection() {
    server_.connections_.erase({client_endpoint_, is_v6_});
}

void UdpServer::Connection::forward_send(
    absl::Span<const uint8_t> chunk, const udp::endpoint &endpoint) {
    remote_socket_.async_send_to(
        buffer(chunk.data(), chunk.size()),
        endpoint,
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code, size_t) {
            connection->server_.forward_receive();
            connection->wait();
        });
}

void UdpServer::Connection::backward_receive() {
    remote_socket_.async_receive_from(
        buffer(
            &backward_buffer_[reserve_header_size_],
            backward_buffer_size_ - reserve_header_size_),
        backward_receive_endpoint_,
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                connection->close();
                return;
            }
            connection->backward_receive_size_ = size;
            connection->backward_send();
            connection->wait();
        });
}

void UdpServer::Connection::backward_send() {
    wire::AddressHeader *header;
    size_t size;
    if (backward_receive_endpoint_.address().is_v4()) {
        header = reinterpret_cast<wire::AddressHeader *>(
            &backward_buffer_[reserve_header_size_ - 7]);
        header->type = wire::AddressType::ipv4;
        header->ipv4_address =
            backward_receive_endpoint_.address().to_v4().to_bytes();
        size = backward_receive_size_ + 7;
    } else {
        header = reinterpret_cast<wire::AddressHeader *>(
            &backward_buffer_[reserve_header_size_ - 19]);
        header->type = wire::AddressType::ipv6;
        header->ipv6_address =
            backward_receive_endpoint_.address().to_v6().to_bytes();
        size = backward_receive_size_ + 19;
    }
    boost::endian::store_big_u16(
        &backward_buffer_[reserve_header_size_ - 2],
        backward_receive_endpoint_.port());
    server_.encrypted_datagram_.send_to(
        {reinterpret_cast<uint8_t *>(header), size},
        client_endpoint_,
        [connection = boost::intrusive_ptr<Connection>(this)](
            std::error_code ec) {
            if (ec) {
                connection->close();
                return;
            }
            connection->backward_receive();
            connection->wait();
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
    timer_.cancel();
    remote_socket_.close();
}

}  // namespace shadowsocks
}  // namespace net
