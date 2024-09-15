#include "net/proxy/http/h2-connection.h"

#include "base/logging.h"
#include "net/proxy/util/write.h"
#include "util/strings.h"

namespace net {
namespace proxy {
namespace http {
namespace {

void populate_nv(
    std::string_view name, std::string_view value, uint8_t flags,
    nghttp2_nv &result) {
    result.name = (uint8_t *)name.data();
    result.namelen = name.size();
    result.value = (uint8_t *)value.data();
    result.valuelen = value.size();
    result.flags = flags;
}

}  // namespace

H2Connection::H2Connection(Stream &stream, const Options &options)
    : stream_(stream),
      read_buffer_(options.read_buffer_size) {
    nghttp2_session_callbacks *callbacks;
    if (nghttp2_session_callbacks_new(&callbacks)) {
        abort();
    }
    nghttp2_session_callbacks_set_on_header_callback(
        callbacks, on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks, on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close);
    if (nghttp2_session_client_new(&session_, callbacks, this)) {
        abort();
    }
    nghttp2_session_callbacks_del(callbacks);
    maybe_write();
    read();
}

H2Connection::~H2Connection() {
    nghttp2_session_del(session_);
}

void H2Connection::request(
    std::string_view method,
    std::string_view scheme,
    std::string_view authority,
    std::string_view path,
    absl::Span<std::pair<std::string, std::string> const> headers,
    absl::AnyInvocable<void(std::error_code, Response)> callback) {
    absl::FixedArray<nghttp2_nv, 0> nvs(4 + headers.size());
    populate_nv(":method", method, NGHTTP2_NV_FLAG_NO_COPY_NAME, nvs[0]);
    populate_nv(":scheme", scheme, NGHTTP2_NV_FLAG_NO_COPY_NAME, nvs[1]);
    populate_nv(":authority", authority, NGHTTP2_NV_FLAG_NO_COPY_NAME, nvs[2]);
    populate_nv(":path", path, NGHTTP2_NV_FLAG_NO_COPY_NAME, nvs[3]);
    size_t index = 4;
    for (const auto &pair : headers) {
        populate_nv(pair.first, pair.second, 0, nvs[index++]);
    }
    int32_t stream_id = nghttp2_submit_request2(
        session_, nullptr, nvs.data(), nvs.size(), nullptr, nullptr);
    ResponseStream response_stream;
    response_stream.callback = std::move(callback);
    response_streams_.emplace(stream_id, std::move(response_stream));
    maybe_write();
}

void H2Connection::read() {
    stream_.read(
        {{read_buffer_.data(), read_buffer_.size()}},
        [this](std::error_code ec, size_t size) {
            if (ec) {
                LOG(error) << "async_read_some failed: " << ec;
                close();
                return;
            }
            nghttp2_ssize rv = nghttp2_session_mem_recv2(
                session_, read_buffer_.data(), size);
            if (rv != static_cast<nghttp2_ssize>(size)) {
                LOG(error) << "nghttp2_session_mem_recv2 failed: " << rv;
                close();
                return;
            }
            if (!nghttp2_session_want_read(session_)) {
                LOG(info) << "session is closed";
                close();
                return;
            }
            read();
        });
}

void H2Connection::maybe_write() {
    if (writing_) {
        return;
    }
    writing_ = true;
    write();
}

void H2Connection::write() {
    // TODO: Buffer writes.
    const uint8_t *data;
    nghttp2_ssize data_size = nghttp2_session_mem_send2(session_, &data);
    if (data_size < 0) {
        LOG(error) << "nghttp2_session_mem_send2 failed: " << data_size;
        writing_ = false;
        return;
    }
    if (!data_size) {
        writing_ = false;
        return;
    }
    proxy::write(
        stream_,
        {data, static_cast<size_t>(data_size)},
        [this](std::error_code ec) {
            if (ec) {
                LOG(error) << "write failed: " << ec;
                writing_ = false;
                return;
            }
            write();
        });
}

void H2Connection::close() {
    auto response_streams_copy = std::move(response_streams_);
    response_streams_.clear();
    for (auto &response_stream : response_streams_copy) {
        std::move(response_stream.second.callback)(
            make_error_code(std::errc::connection_aborted), {});
    }
}

int H2Connection::on_header(
    nghttp2_session *session, const nghttp2_frame *frame,
    const uint8_t *name, size_t namelen,
    const uint8_t *value, size_t valuelen,
    uint8_t flags, void *user_data) {
    auto &connection = *reinterpret_cast<H2Connection *>(user_data);
    if ((frame->hd.type) != NGHTTP2_HEADERS) {
        return 0;
    }
    auto iter = connection.response_streams_.find(frame->hd.stream_id);
    if (iter == connection.response_streams_.end()) {
        LOG(error) << "invalid stream id: " << frame->hd.stream_id;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    Response &response = iter->second.response;
    std::string_view name_sv(reinterpret_cast<const char *>(name), namelen);
    std::string_view value_sv(reinterpret_cast<const char *>(value), valuelen);
    if (name_sv.size() >= 1 && name_sv[0] == ':') {
        if (name_sv == ":status") {
            response.status_code = util::consume_uint32(value_sv);
        }
    } else {
        response.headers.emplace_back(name_sv, value_sv);
    }
    return 0;
}

int H2Connection::on_data_chunk_recv(
    nghttp2_session *session, uint8_t flags, int32_t stream_id,
    const uint8_t *data, size_t len, void *user_data) {
    auto &connection = *reinterpret_cast<H2Connection *>(user_data);
    auto iter = connection.response_streams_.find(stream_id);
    if (iter == connection.response_streams_.end()) {
        LOG(error) << "invalid stream id: " << stream_id;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    std::vector<uint8_t> &body = iter->second.response.body;
    size_t before_size = body.size();
    body.resize(before_size + len);
    memcpy(&body[before_size], data, len);
    return 0;
}

int H2Connection::on_stream_close(
    nghttp2_session *session, int32_t stream_id, uint32_t error_code,
    void *user_data) {
    auto &connection = *reinterpret_cast<H2Connection *>(user_data);
    auto iter = connection.response_streams_.find(stream_id);
    if (iter == connection.response_streams_.end()) {
        LOG(error) << "invalid stream id: " << stream_id;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    ResponseStream response_stream = std::move(iter->second);
    connection.response_streams_.erase(iter);
    std::move(response_stream.callback)(
        {}, std::move(response_stream.response));
    return 0;
}

}  // namespace http
}  // namespace proxy
}  // namespace net
