#include "net/proxy/shadowsocks/decryptor.h"

#include <boost/endian/conversion.hpp>

namespace net {
namespace proxy {
namespace shadowsocks {

Decryptor::Decryptor() : buffer_(131072) {}

bool Decryptor::init(const PreSharedKey &pre_shared_key) {
    size_t salt_size = pre_shared_key.method().salt_size();
    if (buffer_last_ - buffer_first_ < salt_size) {
        return false;
    }
    session_subkey_.init(pre_shared_key, &buffer_[buffer_first_]);
    buffer_first_ += salt_size;
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
        discard();
        return false;
    }
    return true;
}

uint8_t Decryptor::pop_u8() {
    return buffer_[buffer_first_++];
}

uint16_t Decryptor::pop_big_u16() {
    uint16_t result = boost::endian::load_big_u16(&buffer_[buffer_first_]);
    buffer_first_ += 2;
    return result;
}

uint64_t Decryptor::pop_big_u64() {
    uint64_t result = boost::endian::load_big_u64(&buffer_[buffer_first_]);
    buffer_first_ += 8;
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

void Decryptor::advance(size_t size) {
    if (discard_) {
        return;
    }
    buffer_last_ += size;
}

void Decryptor::discard() {
    buffer_first_ = 0;
    buffer_last_ = 0;
    discard_ = true;
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
