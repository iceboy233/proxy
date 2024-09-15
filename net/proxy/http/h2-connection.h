#ifndef _NET_PROXY_HTTP_H2_CONNECTION_H
#define _NET_PROXY_HTTP_H2_CONNECTION_H

#include <nghttp2/nghttp2.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/container/fixed_array.h"
#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "absl/types/span.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {
namespace http {

class H2Connection {
public:
    struct Options {
        size_t read_buffer_size = 65536;
    };

    H2Connection(Stream &stream, const Options &options);
    ~H2Connection();

    struct Response {
        uint32_t status_code;
        std::vector<std::pair<std::string, std::string>> headers;
        std::vector<uint8_t> body;
    };

    void request(
        std::string_view method,
        std::string_view scheme,
        std::string_view authority,
        std::string_view path,
        absl::Span<std::pair<std::string, std::string> const> headers,
        absl::AnyInvocable<void(std::error_code, Response)> callback);

private:
    struct ResponseStream {
        Response response;
        absl::AnyInvocable<void(std::error_code, Response)> callback;
    };

    void read();
    void maybe_write();
    void write();
    void close();

    static int on_header(
        nghttp2_session *session, const nghttp2_frame *frame,
        const uint8_t *name, size_t namelen,
        const uint8_t *value, size_t valuelen,
        uint8_t flags, void *user_data);
    static int on_data_chunk_recv(
        nghttp2_session *session, uint8_t flags, int32_t stream_id,
        const uint8_t *data, size_t len, void *user_data);
    static int on_stream_close(
        nghttp2_session *session, int32_t stream_id, uint32_t error_code,
        void *user_data);

    Stream &stream_;
    nghttp2_session *session_;
    absl::FixedArray<uint8_t, 0> read_buffer_;
    bool writing_ = false;
    absl::flat_hash_map<int32_t, ResponseStream> response_streams_;
};

}  // namespace http
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_HTTP_H2_CONNECTION_H
