#ifndef _NET_PROXY_SHADOWSOCKS_ENCRYPTOR_H
#define _NET_PROXY_SHADOWSOCKS_ENCRYPTOR_H

#include <cstdint>
#include <vector>

#include "base/types.h"
#include "net/proxy/shadowsocks/pre-shared-key.h"
#include "net/proxy/shadowsocks/session-subkey.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class Encryptor {
public:
    void init(const PreSharedKey &pre_shared_key);
    void start_chunk();
    void push_u8(uint8_t value);
    void push_big_u16(uint16_t value);
    void push_big_u64(uint64_t value);
    void push_buffer(ConstBufferSpan buffer);
    void push_random(size_t size);
    void finish_chunk();
    void write_payload_chunk(ConstBufferSpan payload);
    void clear() { buffer_.clear(); }

    const uint8_t *salt() const { return session_subkey_.salt(); }
    ConstBufferSpan buffer() const { return buffer_; }

private:
    SessionSubkey session_subkey_;
    std::vector<uint8_t> buffer_;
    size_t chunk_offset_;
};

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SHADOWSOCKS_ENCRYPTOR_H
