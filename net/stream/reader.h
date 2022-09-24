#ifndef _NET_STREAM_READER_H
#define _NET_STREAM_READER_H

#include <cstddef>
#include <cstdint>
#include <memory>

#include "absl/container/fixed_array.h"
#include "net/asio.h"

namespace net {
namespace stream {

class Reader {
public:
    explicit Reader(size_t capacity);

    template <typename StreamT, typename CallbackT>
    void read(StreamT &stream, size_t size, CallbackT &&callback);

    uint8_t *consume(size_t size);
    size_t size() const { return last_ - first_; }

private:
    absl::FixedArray<uint8_t, 0> array_;
    size_t first_ = 0;
    size_t last_ = 0;
};

template <typename StreamT, typename CallbackT>
void Reader::read(StreamT &stream, size_t size, CallbackT &&callback) {
    size_t remaining_size = Reader::size();
    if (remaining_size >= size) {
        callback({});
        return;
    }
    if (first_) {
        memmove(&array_[0], &array_[first_], remaining_size);
        first_ = 0;
        last_ = remaining_size;
    }
    async_read(
        stream,
        buffer(&array_[last_], array_.size() - last_),
        transfer_at_least(size - remaining_size),
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t transferred_size) mutable {
            last_ += transferred_size;
            callback(ec);
        });
}

}  // namespace stream
}  // namespace net

#endif  // _NET_READER_H
