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
#include "net/stream/reader.h"
#include "util/hash-filter.h"

namespace net {
namespace shadowsocks {

class MasterKey {
public:
    void init(std::string_view method, std::string_view password);

    const EVP_AEAD *aead() const { return aead_; }
    uint8_t *data() { return key_.data(); }
    const uint8_t *data() const { return key_.data(); }
    size_t size() const { return EVP_AEAD_key_length(aead_); }

private:
    const EVP_AEAD *aead_;
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
    EVP_AEAD_CTX aead_ctx_;
    std::array<boost::endian::little_uint64_t, 3> nonce_ = {};
    static_assert(sizeof(nonce_) == 24);
};

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

    tcp::socket &socket_;
    const MasterKey &master_key_;
    SaltFilter *salt_filter_;
    stream::Reader reader_;
    std::unique_ptr<uint8_t[]> write_buffer_;
    static constexpr size_t write_buffer_size_ = 16384 + 66;
    std::optional<SessionKey> read_key_;
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
    size_t offset = 0;
    if (!write_key_) {
        size_t key_size = EVP_AEAD_key_length(master_key_.aead());
        RAND_bytes(&write_buffer_[0], key_size);
        if (salt_filter_) {
            salt_filter_->insert({&write_buffer_[0], key_size});
        }
        write_key_.emplace(master_key_, &write_buffer_[0]);
        offset = key_size;
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
        EVP_AEAD_key_length(master_key_.aead()) + 18,
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            size_t key_size = EVP_AEAD_key_length(master_key_.aead());
            uint8_t *data = reader_.consume(key_size + 18);
            read_key_.emplace(master_key_, data);
            if (!read_key_->decrypt(
                {&data[key_size], 2}, &data[key_size + 2], &data[key_size])) {
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            if (salt_filter_ &&
                !salt_filter_->test_and_insert({data, key_size})) {
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            size_t length = boost::endian::load_big_u16(&data[key_size]);
            if (length >= 16384) {
                callback(make_error_code(std::errc::result_out_of_range), {});
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
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            size_t length = boost::endian::load_big_u16(data);
            if (length >= 16384) {
                callback(make_error_code(std::errc::result_out_of_range), {});
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
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            callback({}, {data, length});
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
            size_t key_size = EVP_AEAD_key_length(master_key_.aead());
            if (size < key_size + 16) {
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            size_t payload_size = size - key_size - 16;
            SessionKey read_key(master_key_, &read_buffer_[0]);
            if (!read_key.decrypt(
                {&read_buffer_[key_size], payload_size},
                &read_buffer_[key_size + payload_size],
                &read_buffer_[key_size])) {
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            if (salt_filter_ &&
                !salt_filter_->test_and_insert({&read_buffer_[0], key_size})) {
                callback(make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            callback({}, {&read_buffer_[key_size], payload_size});
        });
}

template <typename CallbackT>
void EncryptedDatagram::send_to(
    absl::Span<const uint8_t> chunk,
    const udp::endpoint &endpoint,
    CallbackT &&callback) {
    size_t key_size = EVP_AEAD_key_length(master_key_.aead());
    RAND_bytes(&write_buffer_[0], key_size);
    if (salt_filter_) {
        salt_filter_->insert({&write_buffer_[0], key_size});
    }
    SessionKey write_key(master_key_, &write_buffer_[0]);
    write_key.encrypt(
        chunk,
        &write_buffer_[key_size],
        &write_buffer_[key_size + chunk.size()]);
    socket_.async_send_to(
        buffer(&write_buffer_[0], key_size + chunk.size() + 16),
        endpoint,
        [this, callback = std::forward<CallbackT>(callback)](
            std::error_code ec, size_t) mutable {
            callback(ec);
        });
}

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_ENCRYPTION_H
