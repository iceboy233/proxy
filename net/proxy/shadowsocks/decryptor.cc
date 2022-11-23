#include "net/proxy/shadowsocks/decryptor.h"

#include <boost/endian/conversion.hpp>

namespace net {
namespace proxy {
namespace shadowsocks {

Decryptor::Decryptor() : buffer_(131072) {}

bool Decryptor::init(const PreSharedKey &pre_shared_key) {
    if (buffer_last_ - buffer_first_ < pre_shared_key.method().salt_size()) {
        return false;
    }
    session_subkey_.init(pre_shared_key, &buffer_[buffer_first_]);
    buffer_first_ += pre_shared_key.method().salt_size();
    return true;
}

bool Decryptor::start_chunk(size_t size) {
    if (buffer_last_ - buffer_first_ < size + 16) {
        return false;
    }
    if (!session_subkey_.decrypt(
        {&buffer_[buffer_first_], size},
        &buffer_[buffer_first_ + size],
        &buffer_[buffer_first_])) {
        printf("FIXME: handle decrypt failure\n");
        // TODO: in this case, someone should discard the remaining bytes
        return false;
    }
    return true;
}

uint8_t Decryptor::pop_u8() {
    return buffer_[buffer_first_++];
}

uint16_t Decryptor::pop_big_u16() {
    uint16_t result = boost::endian::load_big_u16(&buffer_[buffer_first_]);
    buffer_first_ += sizeof(uint16_t);
    return result;
}

uint8_t *Decryptor::pop_buffer(size_t size) {
    uint8_t *result = &buffer_[buffer_first_];
    buffer_first_ += size;
    return result;
}

void Decryptor::finish_chunk() {
    buffer_first_ += 16;
}

BufferSpan Decryptor::buffer() {
    if (buffer_first_) {
        memmove(
            &buffer_[0], &buffer_[buffer_first_], buffer_last_ - buffer_first_);
        buffer_last_ -= buffer_first_;
        buffer_first_ = 0;
    }
    return {&buffer_[buffer_last_], buffer_.size() - buffer_last_};
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
