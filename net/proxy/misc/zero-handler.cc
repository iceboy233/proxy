#include "net/proxy/misc/zero-handler.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include "absl/container/fixed_array.h"

namespace net {
namespace proxy {
namespace misc {
namespace {

class StreamConnection : public boost::intrusive_ref_counter<
    StreamConnection, boost::thread_unsafe_counter> {
public:
    explicit StreamConnection(std::unique_ptr<Stream> stream);

    void start() { read(); write(); }

private:
    void read();
    void write();
    void close() { stream_->close(); }

    std::unique_ptr<Stream> stream_;
    absl::FixedArray<uint8_t, 0> read_buffer_;
    absl::FixedArray<uint8_t, 0> write_buffer_;
};

class DatagramConnection {
public:
    explicit DatagramConnection(std::unique_ptr<Datagram> datagram);

    void start() { read(); }

private:
    void read();
    void write();
    void finish() { delete this; }

    std::unique_ptr<Datagram> datagram_;
    absl::FixedArray<uint8_t, 0> read_buffer_;
    absl::FixedArray<uint8_t, 0> write_buffer_;
    udp::endpoint endpoint_;
    size_t size_;
};

StreamConnection::StreamConnection(std::unique_ptr<Stream> stream)
    : stream_(std::move(stream)),
      read_buffer_(8192),
      write_buffer_(8192) {}

void StreamConnection::read() {
    stream_->async_read_some(
        buffer(read_buffer_.data(), read_buffer_.size()),
        [connection = boost::intrusive_ptr<StreamConnection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                connection->close();
                return;
            }
            connection->read();
        });
}

void StreamConnection::write() {
    stream_->async_write_some(
        const_buffer(write_buffer_.data(), write_buffer_.size()),
        [connection = boost::intrusive_ptr<StreamConnection>(this)](
            std::error_code ec, size_t) {
            if (ec) {
                connection->close();
                return;
            }
            connection->write();
        });
}

DatagramConnection::DatagramConnection(std::unique_ptr<Datagram> datagram)
    : datagram_(std::move(datagram)),
      read_buffer_(8192),
      write_buffer_(8192) {}

void DatagramConnection::read() {
    datagram_->async_receive_from(
        buffer(read_buffer_.data(), read_buffer_.size()),
        endpoint_,
        [this](std::error_code ec, size_t size) {
            if (ec) {
                finish();
                return;
            }
            size_ = size;
            write();
        });
}

void DatagramConnection::write() {
    datagram_->async_send_to(
        const_buffer(write_buffer_.data(), size_),
        endpoint_,
        [this](std::error_code ec, size_t) {
            if (ec) {
                finish();
                return;
            }
            read();
        });
}

}  // namespace

void ZeroHandler::handle_stream(std::unique_ptr<Stream> stream) {
    boost::intrusive_ptr<StreamConnection> connection(
        new StreamConnection(std::move(stream)));
    connection->start();
}

void ZeroHandler::handle_datagram(std::unique_ptr<Datagram> datagram) {
    auto *connection = new DatagramConnection(std::move(datagram));
    connection->start();
}

}  // namespace misc
}  // namespace proxy
}  // namespace net
