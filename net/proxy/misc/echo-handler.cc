#include "net/proxy/misc/echo-handler.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

#include "absl/container/fixed_array.h"
#include "net/proxy/util/write.h"
#include "net/proxy/const.h"

namespace net {
namespace proxy {
namespace misc {
namespace {

class StreamConnection {
public:
    explicit StreamConnection(std::unique_ptr<Stream> stream);

    void start() { read(); }

private:
    void read();
    void write();
    void finish() { delete this; }

    std::unique_ptr<Stream> stream_;
    absl::FixedArray<uint8_t, 0> buffer_;
    size_t size_;
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
    absl::FixedArray<uint8_t, 0> buffer_;
    udp::endpoint endpoint_;
    size_t size_;
};

StreamConnection::StreamConnection(std::unique_ptr<Stream> stream)
    : stream_(std::move(stream)),
      buffer_(stream_buffer_size) {}

void StreamConnection::read() {
    stream_->read(
        {{buffer_.data(), buffer_.size()}},
        [this](std::error_code ec, size_t size) {
            if (ec) {
                finish();
                return;
            }
            size_ = size;
            write();
        });
}

void StreamConnection::write() {
    proxy::write(*stream_, {buffer_.data(), size_}, [this](std::error_code ec) {
        if (ec) {
            finish();
            return;
        }
        read();
    });
}

DatagramConnection::DatagramConnection(std::unique_ptr<Datagram> datagram)
    : datagram_(std::move(datagram)),
      buffer_(datagram_buffer_size) {}

void DatagramConnection::read() {
    datagram_->receive_from(
        {{buffer_.data(), buffer_.size()}},
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
        {{buffer_.data(), size_}},
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

void EchoHandler::handle_stream(std::unique_ptr<Stream> stream) {
    auto *connection = new StreamConnection(std::move(stream));
    connection->start();
}

void EchoHandler::handle_datagram(std::unique_ptr<Datagram> datagram) {
    auto *connection = new DatagramConnection(std::move(datagram));
    connection->start();
}

}  // namespace misc
}  // namespace proxy
}  // namespace net
