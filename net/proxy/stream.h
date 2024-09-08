#ifndef _NET_PROXY_STREAM_H
#define _NET_PROXY_STREAM_H

#include <cstddef>
#include <system_error>

#include "absl/functional/any_invocable.h"
#include "absl/types/span.h"
#include "net/asio.h"

namespace net {
namespace proxy {

class Stream {
public:
    virtual ~Stream() = default;

    virtual void read(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) = 0;

    virtual void write(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) = 0;

    virtual void close() = 0;
};

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_STREAM_H
