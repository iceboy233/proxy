#include "net/proxy/http/tls-stream.h"

#include <utility>

#include "absl/container/fixed_array.h"

namespace net {
namespace proxy {
namespace http {

TlsStream::TlsStream(
    const any_io_executor &executor,
    Stream &base_stream,
    boost::asio::ssl::context &ssl_context)
    : base_stream_wrapper_(base_stream, executor),
      ssl_stream_(base_stream_wrapper_, ssl_context) {
    // TODO: SSL_set_tlsext_host_name if not numeric host
}

void TlsStream::handshake(
    absl::AnyInvocable<void(std::error_code) &&> callback) {
    ssl_stream_.async_handshake(
        boost::asio::ssl::stream_base::client,
        std::move(callback));
}

void TlsStream::read(
    absl::Span<mutable_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    ssl_stream_.async_read_some(
        absl::FixedArray<mutable_buffer, 1>(buffers.begin(), buffers.end()),
        std::move(callback));
}

void TlsStream::write(
    absl::Span<const_buffer const> buffers,
    absl::AnyInvocable<void(std::error_code, size_t) &&> callback) {
    ssl_stream_.async_write_some(
        absl::FixedArray<const_buffer, 1>(buffers.begin(), buffers.end()),
        std::move(callback));
}

std::string_view TlsStream::alpn_selected() {
    const unsigned char *data;
    unsigned int len;
    SSL_get0_alpn_selected(ssl_stream_.native_handle(), &data, &len);
    return std::string_view(reinterpret_cast<const char *>(data), len);
}

}  // namespace http
}  // namespace proxy
}  // namespace net
