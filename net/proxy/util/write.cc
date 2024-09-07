#include "net/proxy/util/write.h"

#include <utility>

namespace net {
namespace proxy {
namespace {

class WriteOperation {
public:
    WriteOperation(
        Stream &stream,
        ConstBufferSpan buffer,
        absl::AnyInvocable<void(std::error_code) &&> callback);

    void start() { write(); }

private:
    void write();
    void finish(std::error_code ec);

    Stream &stream_;
    ConstBufferSpan buffer_;
    absl::AnyInvocable<void(std::error_code) &&> callback_;
};

WriteOperation::WriteOperation(
    Stream &stream,
    ConstBufferSpan buffer,
    absl::AnyInvocable<void(std::error_code) &&> callback)
    : stream_(stream),
      buffer_(buffer),
      callback_(std::move(callback)) {}

void WriteOperation::write() {
    stream_.write(
        {{buffer_.data(), buffer_.size()}},
        [this](std::error_code ec, size_t size) {
            if (ec) {
                finish(ec);
                return;
            }
            buffer_.remove_prefix(size);
            if (buffer_.empty()) {
                finish({});
                return;
            }
            write();
        });
}

void WriteOperation::finish(std::error_code ec) {
    std::move(callback_)(ec);
    delete this;
}

}  // namespace

void write(
    Stream &stream,
    ConstBufferSpan buffer,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    auto *operation = new WriteOperation(stream, buffer, std::move(callback));
    operation->start();
}

}  // namespace proxy
}  // namespace net
