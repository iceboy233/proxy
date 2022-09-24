#include "net/stream/reader.h"

namespace net {
namespace stream {

Reader::Reader(size_t capacity)
    : array_(capacity) {}

uint8_t *Reader::consume(size_t size) {
    uint8_t *result = &array_[first_];
    first_ += size;
    return result;
}

}  // namespace stream
}  // namespace net
