#include "net/proxy/misc/echo-handler.h"

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
    void write();
    void finish() { delete this; }

    std::unique_ptr<Stream> stream_;
    absl::FixedArray<uint8_t, 0> buffer_;
    size_t size_;
};

StreamConnection::StreamConnection(std::unique_ptr<Stream> stream)
    : stream_(std::move(stream)),
      buffer_(8192) {}

void StreamConnection::read() {
    stream_->async_read_some(
        buffer(buffer_.data(), buffer_.size()),
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
    async_write(
        *stream_,
        buffer(buffer_.data(), size_),
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

}  // namespace misc
}  // namespace proxy
}  // namespace net
