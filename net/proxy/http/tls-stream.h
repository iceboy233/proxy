#ifndef _NET_PROXY_HTTP_TLS_STREAM_H
#define _NET_PROXY_HTTP_TLS_STREAM_H

#include "boost/asio/ssl.hpp"
#include "net/interface/stream.h"
#include "net/proxy/util/stream-wrapper.h"

namespace net {
namespace proxy {
namespace http {

class TlsStream : public Stream {
public:
    TlsStream(
        const any_io_executor &executor,
        Stream &base_stream,
        boost::asio::ssl::context &ssl_context);

    void handshake(absl::AnyInvocable<void(std::error_code) &&> callback);

    void read(
        absl::Span<mutable_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void write(
        absl::Span<const_buffer const> buffers,
        absl::AnyInvocable<void(std::error_code, size_t) &&> callback) override;

    void close() override { base_stream_wrapper_.stream().close(); }

    std::string_view alpn_selected();

private:
    StreamWrapper base_stream_wrapper_;
    boost::asio::ssl::stream<StreamWrapper> ssl_stream_;
};

}  // namespace http
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_HTTP_TLS_STREAM_H
