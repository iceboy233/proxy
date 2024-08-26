#ifndef _NET_PROXY_STREAM_H
#define _NET_PROXY_STREAM_H

#include <cstddef>
#include <system_error>
#include <utility>

#include "absl/functional/any_invocable.h"
#include "absl/types/span.h"
#include "net/asio.h"

namespace net {
namespace proxy {

class Stream {
public:
    using executor_type = any_io_executor;

    virtual ~Stream() = default;

    virtual void read(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) = 0;

    virtual void write(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) = 0;

    virtual any_io_executor get_executor() = 0;
    virtual void close() = 0;

    template <typename BuffersT, typename CallbackT>
    void async_read_some(const BuffersT &buffers, CallbackT &&callback);

    template <typename BuffersT, typename CallbackT>
    void async_write_some(const BuffersT &buffers, CallbackT &&callback);
};

template <typename BuffersT, typename CallbackT>
void Stream::async_read_some(const BuffersT &buffers, CallbackT &&callback) {
    read(
        absl::Span<mutable_buffer const>(
            buffer_sequence_begin(buffers),
            buffer_sequence_end(buffers) - buffer_sequence_begin(buffers)),
        std::forward<CallbackT>(callback));
}

template <typename BuffersT, typename CallbackT>
void Stream::async_write_some(const BuffersT &buffers, CallbackT &&callback) {
    write(
        absl::Span<const_buffer const>(
            buffer_sequence_begin(buffers),
            buffer_sequence_end(buffers) - buffer_sequence_begin(buffers)),
        std::forward<CallbackT>(callback));
}

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_STREAM_H
