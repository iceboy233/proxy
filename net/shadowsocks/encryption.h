#ifndef _NET_SHADOWSOCKS_ENCRYPTION_H
#define _NET_SHADOWSOCKS_ENCRYPTION_H

#include <openssl/aead.h>
#include <openssl/rand.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>
#include <boost/endian/conversion.hpp>

#include "absl/types/span.h"
#include "net/asio.h"
#include "net/proxy/shadowsocks/pre-shared-key.h"
#include "net/proxy/shadowsocks/session-subkey.h"
#include "net/stream/reader.h"
#include "util/hash-filter.h"

namespace net {
namespace shadowsocks {

class SaltFilter {
public:
    SaltFilter();
    bool test_and_insert(absl::Span<const uint8_t> salt);
    void insert(absl::Span<const uint8_t> salt);

private:
    void insert(uint64_t fingerprint);

    util::HashFilter32 filter0_;
    util::HashFilter32 filter1_;
    std::array<uint64_t, 2> key_;
};

class EncryptedStream {
public:
    EncryptedStream(
        tcp::socket &socket,
        const proxy::shadowsocks::PreSharedKey &pre_shared_key,
        SaltFilter *salt_filter);

    template <typename CallbackT>
    void read(CallbackT &&callback);

    template <typename CallbackT>
    void write(absl::Span<const uint8_t> chunk, CallbackT &&callback);

private:
    template <typename CallbackT>
    void read_header(CallbackT &&callback);

    template <typename CallbackT>
    void read_length(CallbackT &&callback);

    template <typename CallbackT>
    void read_payload(size_t length, CallbackT &&callback);

    template <typename CallbackT>
    void read_discard(CallbackT &&callback);

    tcp::socket &socket_;
    const proxy::shadowsocks::PreSharedKey &pre_shared_key_;
    SaltFilter *salt_filter_;
    stream::Reader reader_;
    std::unique_ptr<uint8_t[]> write_buffer_;
    static constexpr size_t write_buffer_size_ = 16384 + 66;
    std::optional<proxy::shadowsocks::SessionSubkey> read_key_;
    std::optional<proxy::shadowsocks::SessionSubkey> write_key_;
};

class EncryptedDatagram {
public:
    EncryptedDatagram(
        udp::socket &socket,
        const proxy::shadowsocks::PreSharedKey &pre_shared_key,
        SaltFilter *salt_filter);

    template <typename CallbackT>
    void receive_from(udp::endpoint &endpoint, CallbackT &&callback);

    template <typename CallbackT>
    void send_to(
        absl::Span<const uint8_t> chunk,
        const udp::endpoint &endpoint,
        CallbackT &&callback);

private:
    udp::socket &socket_;
    const proxy::shadowsocks::PreSharedKey &pre_shared_key_;
    SaltFilter *salt_filter_;
    std::unique_ptr<uint8_t[]> read_buffer_;
    static constexpr size_t read_buffer_size_ = 65535;
    std::unique_ptr<uint8_t[]> write_buffer_;
    static constexpr size_t write_buffer_size_ = 65535;
};

template <typename CallbackT>
void EncryptedStream::read(CallbackT &&callback) {
    if (!read_key_) {
        read_header(std::forward<CallbackT>(callback));
    } else {
        read_length(std::forward<CallbackT>(callback));
    }
}

template <typename CallbackT>
void EncryptedStream::write(
    absl::Span<const uint8_t> chunk, CallbackT &&callback) {
    size_t offset = 0;
    if (!write_key_) {
        size_t salt_size = pre_shared_key_.method().salt_size();
        RAND_bytes(&write_buffer_[0], salt_size);
        if (salt_filter_) {
            salt_filter_->insert({&write_buffer_[0], salt_size});
        }
        write_key_.emplace();
        write_key_->init(pre_shared_key_, &write_buffer_[0]);
        offset = salt_size;
    }
    boost::endian::store_big_u16(&write_buffer_[offset], chunk.size());
    write_key_->encrypt(
        {&write_buffer_[offset], 2},
        &write_buffer_[offset], &write_buffer_[offset + 2]);
    write_key_->encrypt(
        chunk,
        &write_buffer_[offset + 18],
        &write_buffer_[offset + 18 + chunk.size()]);
    async_write(
        socket_,
        buffer(&write_buffer_[0], offset + 18 + chunk.size() + 16),
        [callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t) {
            callback(ec);
        });
}

template <typename CallbackT>
void EncryptedStream::read_header(CallbackT &&callback) {
    reader_.read(
        socket_,
        pre_shared_key_.method().salt_size() + 18,
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            size_t salt_size = pre_shared_key_.method().salt_size();
            uint8_t *data = reader_.consume(salt_size + 18);
            read_key_.emplace();
            read_key_->init(pre_shared_key_, data);
            if (!read_key_->decrypt(
                {&data[salt_size], 2},
                &data[salt_size + 2],
                &data[salt_size])) {
                read_discard(std::forward<CallbackT>(callback));
                return;
            }
            if (salt_filter_ &&
                !salt_filter_->test_and_insert({data, salt_size})) {
                read_discard(std::forward<CallbackT>(callback));
                return;
            }
            size_t length = boost::endian::load_big_u16(&data[salt_size]);
            if (length >= 16384) {
                read_discard(std::forward<CallbackT>(callback));
                return;
            }
            read_payload(length, std::forward<CallbackT>(callback));
        });
}

template <typename CallbackT>
void EncryptedStream::read_length(CallbackT &&callback) {
    reader_.read(
        socket_,
        18,
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            uint8_t *data = reader_.consume(18);
            if (!read_key_->decrypt({data, 2}, &data[2], data)) {
                read_discard(std::forward<CallbackT>(callback));
                return;
            }
            size_t length = boost::endian::load_big_u16(data);
            if (length >= 16384) {
                read_discard(std::forward<CallbackT>(callback));
                return;
            }
            read_payload(length, std::forward<CallbackT>(callback));
        });
}

template <typename CallbackT>
void EncryptedStream::read_payload(size_t length, CallbackT &&callback) {
    reader_.read(
        socket_,
        length + 16,
        [this, length, callback = std::forward<CallbackT>(callback)](
            std::error_code ec) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            uint8_t *data = reader_.consume(length + 16);
            if (!read_key_->decrypt({data, length}, &data[length], data)) {
                read_discard(std::forward<CallbackT>(callback));
                return;
            }
            callback({}, {data, length});
        });
}

template <typename CallbackT>
void EncryptedStream::read_discard(CallbackT &&callback) {
    reader_.read(
        socket_,
        1,
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            reader_.consume(reader_.size());
            read_discard(std::forward<CallbackT>(callback));
        });
}

template <typename CallbackT>
void EncryptedDatagram::receive_from(
    udp::endpoint &endpoint, CallbackT &&callback) {
    socket_.async_receive_from(
        buffer(&read_buffer_[0], read_buffer_size_),
        endpoint,
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t size) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            size_t salt_size = pre_shared_key_.method().salt_size();
            if (size < salt_size + 16) {
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            size_t payload_size = size - salt_size - 16;
            proxy::shadowsocks::SessionSubkey read_key;
            read_key.init(pre_shared_key_, &read_buffer_[0]);
            if (!read_key.decrypt(
                {&read_buffer_[salt_size], payload_size},
                &read_buffer_[salt_size + payload_size],
                &read_buffer_[salt_size])) {
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            if (salt_filter_ &&
                !salt_filter_->test_and_insert({&read_buffer_[0], salt_size})) {
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            callback({}, {&read_buffer_[salt_size], payload_size});
        });
}

template <typename CallbackT>
void EncryptedDatagram::send_to(
    absl::Span<const uint8_t> chunk,
    const udp::endpoint &endpoint,
    CallbackT &&callback) {
    size_t salt_size = pre_shared_key_.method().salt_size();
    RAND_bytes(&write_buffer_[0], salt_size);
    if (salt_filter_) {
        salt_filter_->insert({&write_buffer_[0], salt_size});
    }
    proxy::shadowsocks::SessionSubkey write_key;
    write_key.init(pre_shared_key_, &write_buffer_[0]);
    write_key.encrypt(
        chunk,
        &write_buffer_[salt_size],
        &write_buffer_[salt_size + chunk.size()]);
    socket_.async_send_to(
        buffer(&write_buffer_[0], salt_size + chunk.size() + 16),
        endpoint,
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t) mutable {
            callback(ec);
        });
}

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_ENCRYPTION_H
