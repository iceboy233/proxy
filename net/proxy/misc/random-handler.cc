#include "net/proxy/misc/random-handler.h"

#include <openssl/rand.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include "absl/container/fixed_array.h"
#include "net/proxy/const.h"

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
      read_buffer_(stream_buffer_size),
      write_buffer_(stream_buffer_size) {
    RAND_bytes(write_buffer_.data(), write_buffer_.size());
}

void StreamConnection::read() {
    stream_->read(
        {{read_buffer_.data(), read_buffer_.size()}},
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
    stream_->write(
        {{write_buffer_.data(), write_buffer_.size()}},
        [connection = boost::intrusive_ptr<StreamConnection>(this)](
            std::error_code ec, size_t size) {
            if (ec) {
                connection->close();
                return;
            }
            RAND_bytes(connection->write_buffer_.data(), size);
            connection->write();
        });
}

DatagramConnection::DatagramConnection(std::unique_ptr<Datagram> datagram)
    : datagram_(std::move(datagram)),
      read_buffer_(datagram_buffer_size),
      write_buffer_(datagram_buffer_size) {
    RAND_bytes(write_buffer_.data(), write_buffer_.size());
}

void DatagramConnection::read() {
    datagram_->receive_from(
        {{read_buffer_.data(), read_buffer_.size()}},
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
    datagram_->send_to(
        {{write_buffer_.data(), size_}},
        endpoint_,
        [this](std::error_code ec, size_t size) {
            if (ec) {
                finish();
                return;
            }
            RAND_bytes(write_buffer_.data(), size);
            read();
        });
}

}  // namespace

void RandomHandler::handle_stream(std::unique_ptr<Stream> stream) {
    boost::intrusive_ptr<StreamConnection> connection(
        new StreamConnection(std::move(stream)));
    connection->start();
}

void RandomHandler::handle_datagram(std::unique_ptr<Datagram> datagram) {
    auto *connection = new DatagramConnection(std::move(datagram));
    connection->start();
}

}  // namespace misc
}  // namespace proxy
}  // namespace net
