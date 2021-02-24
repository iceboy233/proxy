#include "net/shadowsocks/aead-crypto.h"

#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <cstdlib>

#include "base/logging.h"

namespace net {
namespace shadowsocks {
namespace {

const std::array<std::pair<std::string_view, AeadMethod>, 4> methods = {{
    {"aes-128-gcm", {EVP_aead_aes_128_gcm(), 16, 16}},
    {"aes-192-gcm", {EVP_aead_aes_192_gcm(), 24, 24}},
    {"aes-256-gcm", {EVP_aead_aes_256_gcm(), 32, 32}},
    {"chacha20-ietf-poly1305", {EVP_aead_chacha20_poly1305(), 32, 32}},
}};

}  // namespace

const AeadMethod &AeadMethod::from_name(std::string_view name) {
    for (const auto &method : methods) {
        if (method.first == name) {
            return method.second;
        }
    }
    LOG(fatal) << "invalid method: " << name;
    abort();
}

void AeadMasterKey::init_with_password(std::string_view password) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, password.data(), password.size());
    MD5_Final(&key_[0], &ctx);
    if (method_.key_size > 16) {
        MD5_Init(&ctx);
        MD5_Update(&ctx, &key_[0], 16);
        MD5_Update(&ctx, password.data(), password.size());
        MD5_Final(&key_[16], &ctx);
    }
}

AeadSessionKey::AeadSessionKey(
    const AeadMasterKey &master_key, const uint8_t *salt) {
    const AeadMethod &method = master_key.method();
    std::array<uint8_t, 32> key;
    if (!HKDF(
        key.data(), method.key_size, EVP_sha1(),
        master_key.data(), master_key.size(), salt, method.salt_size,
        reinterpret_cast<const uint8_t *>("ss-subkey"), 9)) {
        LOG(fatal) << "HKDF failed";
        abort();
    }
    if (!EVP_AEAD_CTX_init(
        &aead_ctx_, method.aead, key.data(), method.key_size, 16, nullptr)) {
        LOG(fatal) << "EVP_AEAD_CTX_init failed";
        abort();
    }
}

AeadSessionKey::~AeadSessionKey() {
    EVP_AEAD_CTX_cleanup(&aead_ctx_);
}

void AeadSessionKey::encrypt(
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

bool AeadSessionKey::decrypt(
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

AeadStream::AeadStream(tcp::socket &socket, const AeadMasterKey &master_key)
    : socket_(socket),
      master_key_(master_key),
      read_buffer_(std::make_unique<uint8_t[]>(read_buffer_size_)),
      write_buffer_(std::make_unique<uint8_t[]>(write_buffer_size_)) {}

void AeadStream::read(
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    if (!read_key_) {
        read_header(std::move(callback));
    } else {
        read_length(std::move(callback));
    }
}

void AeadStream::write(
    absl::Span<const uint8_t> chunk,
    std::function<void(std::error_code)> callback) {
    if (!write_key_) {
        write_header(chunk, std::move(callback));
    } else {
        write_length(chunk, std::move(callback));
    }
}

void AeadStream::read_header(
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    async_read(
        socket_,
        buffer(read_buffer_.get(), master_key_.method().salt_size),
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

void AeadStream::read_length(
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

void AeadStream::read_payload(
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

void AeadStream::write_header(
    absl::Span<const uint8_t> chunk,
    std::function<void(std::error_code)> callback) {
    const size_t salt_size = master_key_.method().salt_size;
    RAND_bytes(write_buffer_.get(), salt_size);
    write_key_.emplace(master_key_, write_buffer_.get());
    write_buffer_[salt_size] = static_cast<uint8_t>(chunk.size() >> 8);
    write_buffer_[salt_size + 1] = static_cast<uint8_t>(chunk.size());
    write_key_->encrypt(
        {&write_buffer_[salt_size], 2},
        &write_buffer_[salt_size],
        &write_buffer_[salt_size + 2]);
    write_key_->encrypt(
        chunk,
        &write_buffer_[salt_size + 18],
        &write_buffer_[salt_size + 18 + chunk.size()]);
    write_payload(chunk.size() + salt_size + 34, std::move(callback));
}

void AeadStream::write_length(
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

void AeadStream::write_payload(
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
