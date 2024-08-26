#ifndef _NET_PROXY_DATAGRAM_H
#define _NET_PROXY_DATAGRAM_H

#include <cstddef>
#include <system_error>
#include <utility>

#include "absl/functional/any_invocable.h"
#include "absl/types/span.h"
#include "net/asio.h"

namespace net {
namespace proxy {

class Datagram {
public:
    using executor_type = any_io_executor;

    virtual ~Datagram() = default;

    virtual void receive_from(
        absl::Span<mutable_buffer const> buffers,
        udp::endpoint &endpoint,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) = 0;

    virtual void send_to(
        absl::Span<const_buffer const> buffers,
        const udp::endpoint &endpoint,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) = 0;

    virtual any_io_executor get_executor() = 0;
    virtual void close() = 0;

    template <typename BuffersT, typename CallbackT>
    void async_receive_from(
        const BuffersT &buffers,
        udp::endpoint &endpoint,
        CallbackT &&callback);

    template <typename BuffersT, typename CallbackT>
    void async_send_to(
        const BuffersT &buffers,
        const udp::endpoint &endpoint,
        CallbackT &&callback);
};

template <typename BuffersT, typename CallbackT>
void Datagram::async_receive_from(
    const BuffersT &buffers,
    udp::endpoint &endpoint,
    CallbackT &&callback) {
    receive_from(
        absl::Span<mutable_buffer const>(
            buffer_sequence_begin(buffers),
            buffer_sequence_end(buffers) - buffer_sequence_begin(buffers)),
        endpoint,
        std::forward<CallbackT>(callback));
}

template <typename BuffersT, typename CallbackT>
void Datagram::async_send_to(
    const BuffersT &buffers,
    const udp::endpoint &endpoint,
    CallbackT &&callback) {
    send_to(
        absl::Span<const_buffer const>(
            buffer_sequence_begin(buffers),
            buffer_sequence_end(buffers) - buffer_sequence_begin(buffers)),
        endpoint,
        std::forward<CallbackT>(callback));
}

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_DATAGRAM_H
