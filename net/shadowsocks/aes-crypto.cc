#include "net/shadowsocks/aes-crypto.h"

#include <stdlib.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>

#include "base/logging.h"

namespace net {
namespace shadowsocks {

AesMasterKey AesMasterKey::from_password(std::string_view password) {
    AesMasterKey key;
    if (!EVP_BytesToKey(
        EVP_aes_128_gcm(), EVP_md5(), nullptr,
        reinterpret_cast<const uint8_t *>(password.data()), password.size(), 1,
        key.data(), nullptr)) {
        LOG(fatal) << "EVP_BytesToKey failed";
        abort();
    }
    return key;
}

AesSessionKey::AesSessionKey(
    const AesMasterKey &master_key, const uint8_t salt[16]) {
    std::array<uint8_t, 16> key;
    if (!HKDF(
        key.data(), key.size(), EVP_sha1(),
        master_key.data(), master_key.size(), salt, 16,
        reinterpret_cast<const uint8_t *>("ss-subkey"), 9)) {
        LOG(fatal) << "HKDF failed";
        abort();
    }
    if (!EVP_AEAD_CTX_init(
        &aead_ctx_, EVP_aead_aes_128_gcm(), key.data(), key.size(), 16,
        nullptr)) {
        LOG(fatal) << "EVP_AEAD_CTX_init failed";
        abort();
    }
}

AesSessionKey::~AesSessionKey() {
    EVP_AEAD_CTX_cleanup(&aead_ctx_);
}

void AesSessionKey::encrypt(
    absl::Span<const uint8_t> in, uint8_t *out, uint8_t out_tag[16]) {
    size_t out_tag_len;
    if (!EVP_AEAD_CTX_seal_scatter(
        &aead_ctx_, out, out_tag, &out_tag_len, 16,
        reinterpret_cast<uint8_t *>(&nonce_low_), 12,
        in.data(), in.size(), nullptr, 0, nullptr, 0) ||
        out_tag_len != 16) {
        LOG(fatal) << "EVP_AEAD_CTX_seal_scatter failed";
        abort();
    }
    if (!++nonce_low_) {
        ++nonce_high_;
    }
}

bool AesSessionKey::decrypt(
    absl::Span<const uint8_t> in, const uint8_t in_tag[16], uint8_t *out) {
    if (!EVP_AEAD_CTX_open_gather(
        &aead_ctx_, out, reinterpret_cast<uint8_t *>(&nonce_low_), 12,
        in.data(), in.size(), in_tag, 16, nullptr, 0)) {
        return false;
    }
    if (!++nonce_low_) {
        ++nonce_high_;
    }
    return true;
}

AesStream::AesStream(tcp::socket &socket, const AesMasterKey &master_key)
    : socket_(socket),
      master_key_(master_key),
      read_buffer_(std::make_unique<uint8_t[]>(read_buffer_size_)),
      write_buffer_(std::make_unique<uint8_t[]>(write_buffer_size_)) {}

void AesStream::read(
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    if (!read_key_) {
        read_header(std::move(callback));
    } else {
        read_length(std::move(callback));
    }
}

void AesStream::write(
    absl::Span<const uint8_t> chunk,
    std::function<void(std::error_code)> callback) {
    if (!write_key_) {
        write_header(chunk, std::move(callback));
    } else {
        write_length(chunk, std::move(callback));
    }
}

void AesStream::read_header(
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    async_read(
        socket_,
        buffer(read_buffer_.get(), 16),
        [this, callback = std::move(callback)](
            std::error_code ec, size_t) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            read_key_.emplace(master_key_, read_buffer_.get());
            read_length(std::move(callback));
        });
}

void AesStream::read_length(
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    async_read(
        socket_,
        buffer(read_buffer_.get(), 18),
        [this, callback = std::move(callback)](
            std::error_code ec, size_t) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            if (!read_key_->decrypt(
                {&read_buffer_[0], 2}, &read_buffer_[2], &read_buffer_[0])) {
                callback(
                    std::make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            size_t length = (read_buffer_[0] << 8) | read_buffer_[1];
            if (length >= 16384) {
                callback(
                    std::make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            read_payload(length, std::move(callback));
        });
}

void AesStream::read_payload(
    size_t length,
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    async_read(
        socket_,
        buffer(read_buffer_.get(), length + 16),
        [this, length, callback = std::move(callback)](
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

void AesStream::write_header(
    absl::Span<const uint8_t> chunk,
    std::function<void(std::error_code)> callback) {
    RAND_bytes(write_buffer_.get(), 16);
    write_key_.emplace(master_key_, write_buffer_.get());
    write_buffer_[16] = static_cast<uint8_t>(chunk.size() >> 8);
    write_buffer_[17] = static_cast<uint8_t>(chunk.size());
    write_key_->encrypt(
        {&write_buffer_[16], 2}, &write_buffer_[16], &write_buffer_[18]);
    write_key_->encrypt(
        chunk, &write_buffer_[34], &write_buffer_[34 + chunk.size()]);
    write_payload(chunk.size() + 50, std::move(callback));
}

void AesStream::write_length(
    absl::Span<const uint8_t> chunk,
    std::function<void(std::error_code)> callback) {
    write_buffer_[0] = static_cast<uint8_t>(chunk.size() >> 8);
    write_buffer_[1] = static_cast<uint8_t>(chunk.size());
    write_key_->encrypt(
        {&write_buffer_[0], 2}, &write_buffer_[0], &write_buffer_[2]);
    write_key_->encrypt(
        chunk, &write_buffer_[18], &write_buffer_[18 + chunk.size()]);
    write_payload(chunk.size() + 34, std::move(callback));
}

void AesStream::write_payload(
    size_t length,
    std::function<void(std::error_code)> callback) {
    async_write(
        socket_,
        buffer(write_buffer_.get(), length),
        [callback = std::move(callback)](std::error_code ec, size_t) {
            callback(ec);
        });
}

}  // namespace shadowsocks
}  // namespace net
