#include "net/proxy/system/stdio-stream.h"

#include "absl/container/fixed_array.h"

namespace net {
namespace proxy {
namespace system {

StdioStream::StdioStream(const any_io_executor &executor)
    : stdin_(executor, STDIN_FILENO),
      stdout_(executor, STDOUT_FILENO) {}

void StdioStream::async_read_some(
    absl::Span<mutable_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    stdin_.async_read_some(
        absl::FixedArray<mutable_buffer, 1>(buffers.begin(), buffers.end()),
        std::move(callback));
}

void StdioStream::async_write_some(
    absl::Span<const_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    stdout_.async_write_some(
        absl::FixedArray<const_buffer, 1>(buffers.begin(), buffers.end()),
        std::move(callback));
}

void StdioStream::close() {
    boost::system::error_code ec;
    stdin_.close(ec);
    stdout_.close(ec);
}

}  // namespace system
}  // namespace proxy
}  // namespace net
