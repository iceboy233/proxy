#include "net/proxy/system/tcp-socket-stream.h"

#include "absl/container/fixed_array.h"

namespace net {
namespace proxy {
namespace system {

void TcpSocketStream::async_read_some(
    absl::Span<mutable_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    socket_.async_read_some(
        absl::FixedArray<mutable_buffer, 1>(buffers.begin(), buffers.end()),
        std::move(callback));
}

void TcpSocketStream::async_write_some(
    absl::Span<const_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    socket_.async_write_some(
        absl::FixedArray<const_buffer, 1>(buffers.begin(), buffers.end()),
        std::move(callback));
}

}  // namespace proxy
}  // namespace system
}  // namespace net
