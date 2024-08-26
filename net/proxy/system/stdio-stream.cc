#include "net/proxy/system/stdio-stream.h"

#include "absl/container/fixed_array.h"
#ifdef _WIN32
#include "io/file-utils.h"
#endif

namespace net {
namespace proxy {
namespace system {

StdioStream::StdioStream(const any_io_executor &executor)
    : executor_(executor),
#ifndef _WIN32
      stdin_(executor, STDIN_FILENO),
      stdout_(executor, STDOUT_FILENO)
#else
      stdin_thread_(1),
      stdout_thread_(1),
      stdin_(io::std_input()),
      stdout_(io::std_output())
#endif
    {}

void StdioStream::read(
    absl::Span<mutable_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
#ifndef _WIN32
    stdin_.async_read_some(
        absl::FixedArray<mutable_buffer, 1>(buffers.begin(), buffers.end()),
        std::move(callback));
#else
    post(
        stdin_thread_,
        [this, buffers, callback = std::move(callback)]() mutable {
            if (buffers.empty()) {
                std::move(callback)({}, 0);
                return;
            }
            size_t size;
            std::error_code ec = stdin_.read(
                {buffers.front().data(), buffers.front().size()}, size);
            if (ec) {
                std::move(callback)(ec, 0);
                return;
            }
            std::move(callback)({}, size);
        });
#endif
}

void StdioStream::write(
    absl::Span<const_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
#ifndef _WIN32
    stdout_.async_write_some(
        absl::FixedArray<const_buffer, 1>(buffers.begin(), buffers.end()),
        std::move(callback));
#else
    post(
        stdout_thread_,
        [this, buffers, callback = std::move(callback)]() mutable {
            size_t size = 0;
            for (const_buffer buffer : buffers) {
                std::error_code ec = io::write(
                    stdout_, {buffer.data(), buffer.size()});
                if (ec) {
                    std::move(callback)(ec, size);
                    return;
                }
                size += buffer.size();
            }
            std::move(callback)({}, size);
        });
#endif
}

void StdioStream::close() {
#ifndef _WIN32
    boost::system::error_code ec;
    stdin_.close(ec);
    stdout_.close(ec);
#endif
}

}  // namespace system
}  // namespace proxy
}  // namespace net
