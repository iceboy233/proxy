#include "net/proxy/system/udp-socket-datagram.h"

#include "absl/container/fixed_array.h"

namespace net {
namespace proxy {
namespace system {

void UdpSocketDatagram::async_receive_from(
    absl::Span<mutable_buffer const> buffers,
    udp::endpoint &endpoint,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    socket_.async_receive_from(
        absl::FixedArray<mutable_buffer, 1>(buffers.begin(), buffers.end()),
        endpoint,
        std::move(callback));
}

void UdpSocketDatagram::async_send_to(
    absl::Span<const_buffer const> buffers,
    const udp::endpoint &endpoint,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    socket_.async_send_to(
        absl::FixedArray<const_buffer, 1>(buffers.begin(), buffers.end()),
        endpoint,
        std::move(callback));
}

}  // namespace proxy
}  // namespace system
}  // namespace net
