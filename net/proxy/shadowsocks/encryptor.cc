#include "net/proxy/shadowsocks/encryptor.h"

#include <openssl/rand.h>
#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>

namespace net {
namespace proxy {
namespace shadowsocks {

void Encryptor::init(const PreSharedKey &pre_shared_key) {
    buffer_.resize(pre_shared_key.method().salt_size());
    RAND_bytes(&buffer_[0], buffer_.size());
    session_subkey_.init(pre_shared_key, &buffer_[0]);
}

void Encryptor::start_chunk() {
    chunk_offset_ = buffer_.size();
}

void Encryptor::push_u8(uint8_t value) {
    buffer_.push_back(value);
}

void Encryptor::push_big_u16(uint16_t value) {
    size_t offset = buffer_.size();
    buffer_.resize(offset + 2);
    boost::endian::store_big_u16(&buffer_[offset], value);
}

void Encryptor::push_big_u64(uint64_t value) {
    size_t offset = buffer_.size();
    buffer_.resize(offset + 8);
    boost::endian::store_big_u64(&buffer_[offset], value);
}

void Encryptor::push_buffer(ConstBufferSpan buffer) {
    size_t offset = buffer_.size();
    buffer_.resize(offset + buffer.size());
    memcpy(&buffer_[offset], buffer.data(), buffer.size());
}

void Encryptor::push_random(size_t size) {
    size_t offset = buffer_.size();
    buffer_.resize(offset + size);
    RAND_bytes(&buffer_[offset], size);
}

void Encryptor::finish_chunk() {
    size_t offset = buffer_.size();
    buffer_.resize(offset + 16);
    session_subkey_.encrypt(
        {&buffer_[chunk_offset_], offset - chunk_offset_},
        &buffer_[chunk_offset_],
        &buffer_[offset]);
}

void Encryptor::write_payload_chunk(ConstBufferSpan payload) {
    size_t offset = buffer_.size();
    buffer_.resize(offset + payload.size() + 16);
    session_subkey_.encrypt(
        payload, &buffer_[offset], &buffer_[offset + payload.size()]);
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
