#ifndef _NET_PROXY_UTIL_WRITE_H
#define _NET_PROXY_UTIL_WRITE_H

#include <system_error>

#include "absl/functional/any_invocable.h"
#include "base/types.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {

void write(
    Stream &stream,
    ConstBufferSpan buffer,
    absl::AnyInvocable<void(std::error_code) &&> callback);

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_UTIL_WRITE_H
