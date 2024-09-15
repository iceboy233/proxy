#ifndef _NET_PROXY_UTIL_STREAM_WRAPPER_H
#define _NET_PROXY_UTIL_STREAM_WRAPPER_H

#include <utility>

#include "absl/types/span.h"
#include "net/asio.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {

class StreamWrapper {
public:
    using executor_type = any_io_executor;
    using lowest_layer_type = StreamWrapper;

    StreamWrapper(Stream &stream, const any_io_executor &executor)
        : stream_(stream), executor_(executor) {}

    template <typename BuffersT, typename CallbackT>
    void async_read_some(const BuffersT &buffers, CallbackT &&callback);

    template <typename BuffersT, typename CallbackT>
    void async_write_some(const BuffersT &buffers, CallbackT &&callback);

    Stream &stream() { return stream_; }
    const any_io_executor &get_executor() { return executor_; }

    StreamWrapper &lowest_layer() { return *this; }
    const StreamWrapper &lowest_layer() const { return *this; }

private:
    Stream &stream_;
    any_io_executor executor_;
};

template <typename BuffersT, typename CallbackT>
void StreamWrapper::async_read_some(
    const BuffersT &buffers, CallbackT &&callback) {
    stream_.read(
        absl::Span<mutable_buffer const>(
            buffer_sequence_begin(buffers),
            buffer_sequence_end(buffers) - buffer_sequence_begin(buffers)),
        std::forward<CallbackT>(callback));
}

template <typename BuffersT, typename CallbackT>
void StreamWrapper::async_write_some(
    const BuffersT &buffers, CallbackT &&callback) {
    stream_.write(
        absl::Span<const_buffer const>(
            buffer_sequence_begin(buffers),
            buffer_sequence_end(buffers) - buffer_sequence_begin(buffers)),
        std::forward<CallbackT>(callback));
}

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_UTIL_STREAM_WRAPPER_H
