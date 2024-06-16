#ifndef _NET_PROXY_SYSTEM_STDIO_STREAM_H
#define _NET_PROXY_SYSTEM_STDIO_STREAM_H

#ifdef _WIN32
#include "io/native-file.h"
#endif
#include "net/asio.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {
namespace system {

class StdioStream : public Stream {
public:
    explicit StdioStream(const any_io_executor &executor);

    StdioStream(const StdioStream &) = delete;
    StdioStream &operator=(const StdioStream &) = delete;

    void async_read_some(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void async_write_some(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    any_io_executor get_executor() override { return executor_; }
    void close() override;

private:
    any_io_executor executor_;
#ifndef _WIN32
    readable_pipe stdin_;
    writable_pipe stdout_;
#else
    static_thread_pool stdin_thread_;
    static_thread_pool stdout_thread_;
    io::NativeSharedFile stdin_;
    io::NativeSharedFile stdout_;
#endif  // _WIN32
};

}  // namespace system
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SYSTEM_STDIO_STREAM_H
