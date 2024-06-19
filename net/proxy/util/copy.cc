#include "net/proxy/util/copy.h"

#include <cstddef>
#include <utility>

#include "absl/container/fixed_array.h"

namespace net {
namespace proxy {
namespace {

class CopyBidirOperation {
public:
    CopyBidirOperation(
        std::unique_ptr<Stream> stream0,
        std::unique_ptr<Stream> stream1,
        absl::AnyInvocable<void(std::error_code) &&> callback);

    void start();

private:
    void forward_read();
    void forward_write();
    void backward_read();
    void backward_write();
    void finish_one(std::error_code ec);

    std::unique_ptr<Stream> stream0_;
    std::unique_ptr<Stream> stream1_;
    absl::AnyInvocable<void(std::error_code) &&> callback_;
    absl::FixedArray<uint8_t, 0> forward_buffer_;
    size_t forward_size_;
    absl::FixedArray<uint8_t, 0> backward_buffer_;
    size_t backward_size_;
    int finish_count_ = 0;
};

CopyBidirOperation::CopyBidirOperation(
    std::unique_ptr<Stream> stream0,
    std::unique_ptr<Stream> stream1,
    absl::AnyInvocable<void(std::error_code) &&> callback)
    : stream0_(std::move(stream0)),
      stream1_(std::move(stream1)),
      callback_(std::move(callback)),
      forward_buffer_(8192),
      backward_buffer_(8192) {}

void CopyBidirOperation::start() {
    forward_read();
    backward_read();
}

void CopyBidirOperation::forward_read() {
    stream0_->async_read_some(
        buffer(forward_buffer_.data(), forward_buffer_.size()),
        [this](std::error_code ec, size_t size) {
            if (ec) {
                finish_one(ec);
                return;
            }
            forward_size_ = size;
            forward_write();
        });
}

void CopyBidirOperation::forward_write() {
    async_write(
        *stream1_,
        buffer(forward_buffer_.data(), forward_size_),
        [this](std::error_code ec, size_t) {
            if (ec) {
                finish_one(ec);
                return;
            }
            forward_read();
        });
}

void CopyBidirOperation::backward_read() {
    stream1_->async_read_some(
        buffer(backward_buffer_.data(), backward_buffer_.size()),
        [this](std::error_code ec, size_t size) {
            if (ec) {
                finish_one(ec);
                return;
            }
            backward_size_ = size;
            backward_write();
        });
}

void CopyBidirOperation::backward_write() {
    async_write(
        *stream0_,
        buffer(backward_buffer_.data(), backward_size_),
        [this](std::error_code ec, size_t) {
            if (ec) {
                finish_one(ec);
                return;
            }
            backward_read();
        });
}

void CopyBidirOperation::finish_one(std::error_code ec) {
    switch (++finish_count_) {
    case 1:
        std::move(callback_)(ec);
        callback_ = {};
        stream0_->close();
        stream1_->close();
        break;
    case 2:
        delete this;
        break;
    }
}

}  // namespace

void copy_bidir(
    std::unique_ptr<Stream> stream0,
    std::unique_ptr<Stream> stream1,
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    auto *operation = new CopyBidirOperation(
        std::move(stream0), std::move(stream1), std::move(callback));
    operation->start();
}

}  // namespace proxy
}  // namespace net
