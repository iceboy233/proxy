#ifndef _NET_PROXY_UTIL_COPY_H
#define _NET_PROXY_UTIL_COPY_H

#include <memory>
#include <system_error>

#include "absl/functional/any_invocable.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {

void copy_bidir(
    std::unique_ptr<Stream> stream0,
    std::unique_ptr<Stream> stream1,
    absl::AnyInvocable<void(std::error_code)> callback);

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_UTIL_COPY_H
