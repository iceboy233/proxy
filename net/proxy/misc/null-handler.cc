#include "net/proxy/misc/null-handler.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

#include "absl/container/fixed_array.h"

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
    void finish() { delete this; }

    std::unique_ptr<Stream> stream_;
    absl::FixedArray<uint8_t, 0> buffer_;
};

class DatagramConnection {
public:
    explicit DatagramConnection(std::unique_ptr<Datagram> datagram);

    void start() { read(); }

private:
    void read();
    void finish() { delete this; }

    std::unique_ptr<Datagram> datagram_;
    absl::FixedArray<uint8_t, 0> buffer_;
    udp::endpoint endpoint_;
};

StreamConnection::StreamConnection(std::unique_ptr<Stream> stream)
    : stream_(std::move(stream)),
      buffer_(8192) {}

void StreamConnection::read() {
    stream_->read(
        {{buffer_.data(), buffer_.size()}},
        [this](std::error_code ec, size_t) {
            if (ec) {
                finish();
                return;
            }
            read();
        });
}

DatagramConnection::DatagramConnection(std::unique_ptr<Datagram> datagram)
    : datagram_(std::move(datagram)),
      buffer_(8192) {}

void DatagramConnection::read() {
    datagram_->receive_from(
        {{buffer_.data(), buffer_.size()}},
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

void NullHandler::handle_stream(std::unique_ptr<Stream> stream) {
    auto *connection = new StreamConnection(std::move(stream));
    connection->start();
}

void NullHandler::handle_datagram(std::unique_ptr<Datagram> datagram) {
    auto *connection = new DatagramConnection(std::move(datagram));
    connection->start();
}

}  // namespace misc
}  // namespace proxy
}  // namespace net
