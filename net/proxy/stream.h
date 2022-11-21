#ifndef _NET_PROXY_STREAM_H
#define _NET_PROXY_STREAM_H

#include <cstddef>
#include <memory>
#include <system_error>

#include "absl/functional/any_invocable.h"
#include "absl/types/span.h"
#include "net/asio.h"

namespace net {

class Stream {
public:
    using executor_type = any_io_executor;

    virtual ~Stream() = default;
    virtual any_io_executor get_executor() = 0;

    virtual void async_read_some(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) = 0;

    virtual void async_write_some(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) = 0;

    template <typename BuffersT>
    void async_read_some(
        const BuffersT &buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback);

    template <typename BuffersT>
    void async_write_some(
        const BuffersT &buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback);
};

template <typename BuffersT>
void Stream::async_read_some(
    const BuffersT &buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    async_read_some(
        absl::Span<mutable_buffer const>(
            buffer_sequence_begin(buffers),
            buffer_sequence_end(buffers) - buffer_sequence_begin(buffers)),
        std::move(callback));
}

template <typename BuffersT>
void Stream::async_write_some(
    const BuffersT &buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    async_write_some(
        absl::Span<const_buffer const>(
            buffer_sequence_begin(buffers),
            buffer_sequence_end(buffers) - buffer_sequence_begin(buffers)),
        std::move(callback));
}

}  // namespace net

#endif  // _NET_PROXY_STREAM_H
