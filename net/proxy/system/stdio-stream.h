#ifndef _NET_PROXY_SYSTEM_STDIO_STREAM_H
#define _NET_PROXY_SYSTEM_STDIO_STREAM_H

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

    any_io_executor get_executor() override { return stdin_.get_executor(); }
    void close() override;

private:
    boost::asio::posix::stream_descriptor stdin_;
    boost::asio::posix::stream_descriptor stdout_;
};

}  // namespace system
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SYSTEM_STDIO_STREAM_H
