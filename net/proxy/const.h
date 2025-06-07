#ifndef _NET_PROXY_CONST_H
#define _NET_PROXY_CONST_H

#include <cstddef>

namespace net {
namespace proxy {

constexpr size_t stream_buffer_size = 65536;
constexpr size_t datagram_buffer_size = 8192;

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_CONST_H
