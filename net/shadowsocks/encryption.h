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
#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>

#include "absl/types/span.h"
#include "net/asio.h"
#include "net/shadowsocks/hash-filter.h"

namespace net {
namespace shadowsocks {

struct EncryptionMethod {
    const EVP_AEAD *aead;
    size_t salt_size;
    size_t key_size;

    static const EncryptionMethod &from_name(std::string_view name);
};

class MasterKey {
public:
    explicit MasterKey(const EncryptionMethod &method) : method_(method) {}

    void init_with_password(std::string_view password);

    uint8_t *data() { return key_.data(); }
    const uint8_t *data() const { return key_.data(); }
    size_t size() const { return method_.key_size; }
    const EncryptionMethod &method() const { return method_; }

private:
    const EncryptionMethod &method_;
    std::array<uint8_t, 32> key_;
};

class SessionKey {
public:
    SessionKey(const MasterKey &master_key, const uint8_t *salt);
    ~SessionKey();

    void encrypt(
        absl::Span<const uint8_t> in, uint8_t *out, uint8_t out_tag[16]);
    bool decrypt(
        absl::Span<const uint8_t> in, const uint8_t in_tag[16], uint8_t *out);

private:
    struct Nonce {
        boost::endian::little_uint64_t low = 0;
        boost::endian::little_uint32_t high = 0;
    };
    static_assert(sizeof(Nonce) == 12);

    EVP_AEAD_CTX aead_ctx_;
    Nonce nonce_;
};

class SaltFilter {
public:
    SaltFilter();
    bool test_and_insert(absl::Span<const uint8_t> salt);

private:
    HashFilter *current_;
    std::array<HashFilter, 2> filters_;
    std::array<uint64_t, 2> key_;
};

class EncryptedStream {
public:
    EncryptedStream(
        tcp::socket &socket,
        const MasterKey &master_key,
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
    void write_header(absl::Span<const uint8_t> chunk, CallbackT &&callback);

    template <typename CallbackT>
    void write_length(
        absl::Span<const uint8_t> chunk, size_t offset, CallbackT &&callback);

    template <typename CallbackT>
    void write_payload(size_t size, CallbackT &&callback);

    tcp::socket &socket_;
    const MasterKey &master_key_;
    SaltFilter *salt_filter_;
    std::unique_ptr<uint8_t[]> read_buffer_;
    static constexpr size_t read_buffer_size_ = 16384 + 16;
    std::unique_ptr<uint8_t[]> write_buffer_;
    static constexpr size_t write_buffer_size_ = 16384 + 66;
    std::optional<SessionKey> read_key_;
    bool read_key_allowed_ = false;
    std::optional<SessionKey> write_key_;
};

class EncryptedDatagram {
public:
    EncryptedDatagram(
        udp::socket &socket,
        const MasterKey &master_key,
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
    const MasterKey &master_key_;
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
    if (!write_key_) {
        write_header(chunk, std::forward<CallbackT>(callback));
    } else {
        write_length(chunk, 0, std::forward<CallbackT>(callback));
    }
}

template <typename CallbackT>
void EncryptedStream::read_header(CallbackT &&callback) {
    async_read(
        socket_,
        buffer(&read_buffer_[0], master_key_.method().salt_size),
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            read_key_.emplace(master_key_, &read_buffer_[0]);
            read_length(std::forward<CallbackT>(callback));
        });
}

template <typename CallbackT>
void EncryptedStream::read_length(CallbackT &&callback) {
    async_read(
        socket_,
        buffer(&read_buffer_[32], 18),
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            if (!read_key_->decrypt(
                {&read_buffer_[32], 2}, &read_buffer_[34], &read_buffer_[32])) {
                callback(
                    std::make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            if (salt_filter_ && !read_key_allowed_) {
                if (!salt_filter_->test_and_insert(
                    {&read_buffer_[0], master_key_.method().salt_size})) {
                    callback(
                        std::make_error_code(std::errc::result_out_of_range),
                        {});
                    return;
                }
                read_key_allowed_ = true;
            }
            size_t length = boost::endian::load_big_u16(&read_buffer_[32]);
            if (length >= 16384) {
                callback(
                    std::make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            read_payload(length, std::forward<CallbackT>(callback));
        });
}

template <typename CallbackT>
void EncryptedStream::read_payload(size_t length, CallbackT &&callback) {
    async_read(
        socket_,
        buffer(&read_buffer_[0], length + 16),
        [this, length, callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t) {
            if (ec) {
                callback(ec, {});
                return;
            }
            if (!read_key_->decrypt(
                {&read_buffer_[0], length}, &read_buffer_[length],
                &read_buffer_[0])) {
                callback(
                    std::make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            callback({}, {&read_buffer_[0], length});
        });
}

template <typename CallbackT>
void EncryptedStream::write_header(
    absl::Span<const uint8_t> chunk, CallbackT &&callback) {
    const size_t salt_size = master_key_.method().salt_size;
    RAND_bytes(&write_buffer_[0], salt_size);
    write_key_.emplace(master_key_, &write_buffer_[0]);
    write_length(chunk, salt_size, std::forward<CallbackT>(callback));
}

template <typename CallbackT>
void EncryptedStream::write_length(
    absl::Span<const uint8_t> chunk, size_t offset, CallbackT &&callback) {
    write_buffer_[offset] = static_cast<uint8_t>(chunk.size() >> 8);
    write_buffer_[offset + 1] = static_cast<uint8_t>(chunk.size());
    write_key_->encrypt(
        {&write_buffer_[offset], 2},
        &write_buffer_[offset], &write_buffer_[offset + 2]);
    write_key_->encrypt(
        chunk,
        &write_buffer_[offset + 18],
        &write_buffer_[offset + 18 + chunk.size()]);
    write_payload(
        offset + chunk.size() + 34, std::forward<CallbackT>(callback));
}

template <typename CallbackT>
void EncryptedStream::write_payload(size_t size, CallbackT &&callback) {
    async_write(
        socket_,
        buffer(&write_buffer_[0], size),
        [callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t) {
            callback(ec);
        });
}

template <typename CallbackT>
void EncryptedDatagram::receive_from(
    udp::endpoint &endpoint, CallbackT &&callback) {
    socket_.async_receive_from(
        buffer(read_buffer_.get(), read_buffer_size_),
        endpoint,
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t size) {
            if (ec) {
                callback(ec, {});
                return;
            }
            size_t salt_size = master_key_.method().salt_size;
            size_t payload_len = size - salt_size - 16;
            SessionKey read_key(master_key_, read_buffer_.get());
            if (!read_key.decrypt(
                {&read_buffer_[salt_size], payload_len},
                &read_buffer_[size - 16],
                &read_buffer_[salt_size])) {
                callback(
                    std::make_error_code(std::errc::result_out_of_range),
                    {});
                return;
            }
            if (salt_filter_) {
                if (!salt_filter_->test_and_insert(
                    {&read_buffer_[0], master_key_.method().salt_size})) {
                    callback(
                        std::make_error_code(std::errc::result_out_of_range),
                        {});
                    return;
                }
            }
            callback({}, {&read_buffer_[salt_size], payload_len});
        });
}

template <typename CallbackT>
void EncryptedDatagram::send_to(
    absl::Span<const uint8_t> chunk,
    const udp::endpoint &endpoint,
    CallbackT &&callback) {
    const size_t salt_size = master_key_.method().salt_size;
    RAND_bytes(write_buffer_.get(), salt_size);
    SessionKey write_key(master_key_, write_buffer_.get());
    write_key.encrypt(
        chunk, &write_buffer_[salt_size],
        &write_buffer_[salt_size + chunk.size()]);
    socket_.async_send_to(
        buffer(write_buffer_.get(), salt_size + chunk.size() + 16),
        endpoint,
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t) {
            callback(ec);
        });
}

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_ENCRYPTION_H
