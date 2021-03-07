#include "net/shadowsocks/encryption.h"

#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/siphash.h>
#include <cstdlib>

#include "base/flags.h"
#include "base/logging.h"

DEFINE_FLAG(bool, detect_salt_reuse, true,
            "Detect salt reuse to prevent replay attacks.");

namespace net {
namespace shadowsocks {
namespace {

const std::array<std::pair<std::string_view, EncryptionMethod>, 4> methods = {{
    {"aes-128-gcm", {EVP_aead_aes_128_gcm(), 16, 16}},
    {"aes-192-gcm", {EVP_aead_aes_192_gcm(), 24, 24}},
    {"aes-256-gcm", {EVP_aead_aes_256_gcm(), 32, 32}},
    {"chacha20-ietf-poly1305", {EVP_aead_chacha20_poly1305(), 32, 32}},
}};

}  // namespace

const EncryptionMethod &EncryptionMethod::from_name(std::string_view name) {
    for (const auto &method : methods) {
        if (method.first == name) {
            return method.second;
        }
    }
    LOG(fatal) << "invalid method: " << name;
    abort();
}

void MasterKey::init_with_password(std::string_view password) {
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

SessionKey::SessionKey(
    const MasterKey &master_key, const uint8_t *salt) {
    const EncryptionMethod &method = master_key.method();
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

SessionKey::~SessionKey() {
    EVP_AEAD_CTX_cleanup(&aead_ctx_);
}

void SessionKey::encrypt(
    absl::Span<const uint8_t> in, uint8_t *out, uint8_t out_tag[16]) {
    size_t out_tag_len;
    if (!EVP_AEAD_CTX_seal_scatter(
        &aead_ctx_, out, out_tag, &out_tag_len, 16,
        reinterpret_cast<uint8_t *>(&nonce_), sizeof(nonce_),
        in.data(), in.size(), nullptr, 0, nullptr, 0) ||
        out_tag_len != 16) {
        LOG(fatal) << "EVP_AEAD_CTX_seal_scatter failed";
        abort();
    }
    if (!++nonce_.low) {
        ++nonce_.high;
    }
}

bool SessionKey::decrypt(
    absl::Span<const uint8_t> in, const uint8_t in_tag[16], uint8_t *out) {
    if (!EVP_AEAD_CTX_open_gather(
        &aead_ctx_, out, reinterpret_cast<uint8_t *>(&nonce_), sizeof(nonce_),
        in.data(), in.size(), in_tag, 16, nullptr, 0)) {
        return false;
    }
    if (!++nonce_.low) {
        ++nonce_.high;
    }
    return true;
}

SaltFilter::SaltFilter()
    : current_(&filters_[0]) {
    RAND_bytes(reinterpret_cast<uint8_t *>(key_.data()), sizeof(key_));
}

bool SaltFilter::test_and_insert(absl::Span<const uint8_t> salt) {
    uint64_t fingerprint = SIPHASH_24(key_.data(), salt.data(), salt.size());
    if (filters_[0].test(fingerprint) || filters_[1].test(fingerprint)) {
        return false;
    }
    if (current_->size() >= 800000) {
        current_ = current_ == &filters_[0] ? &filters_[1] : &filters_[0];
        current_->clear();
    }
    current_->insert(fingerprint);
    return true;
}

EncryptedStream::EncryptedStream(
    tcp::socket &socket, const MasterKey &master_key, SaltFilter &salt_filter)
    : socket_(socket),
      master_key_(master_key),
      salt_filter_(salt_filter),
      read_buffer_(std::make_unique<uint8_t[]>(read_buffer_size_)),
      write_buffer_(std::make_unique<uint8_t[]>(write_buffer_size_)) {}

void EncryptedStream::read(
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    if (!read_key_) {
        read_header(std::move(callback));
    } else {
        read_length(std::move(callback));
    }
}

void EncryptedStream::write(
    absl::Span<const uint8_t> chunk,
    std::function<void(std::error_code)> callback) {
    if (!write_key_) {
        write_header(chunk, std::move(callback));
    } else {
        write_length(chunk, 0, std::move(callback));
    }
}

void EncryptedStream::read_header(
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    async_read(
        socket_,
        buffer(&read_buffer_[0], master_key_.method().salt_size),
        [this, callback = std::move(callback)](
            std::error_code ec, size_t) mutable {
            if (ec) {
                callback(ec, {});
                return;
            }
            read_key_.emplace(master_key_, &read_buffer_[0]);
            read_length(std::move(callback));
        });
}

void EncryptedStream::read_length(
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    async_read(
        socket_,
        buffer(&read_buffer_[32], 18),
        [this, callback = std::move(callback)](
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
            if (flags::detect_salt_reuse && !read_key_allowed_) {
                if (!salt_filter_.test_and_insert(
                    {&read_buffer_[0], master_key_.method().salt_size})) {
                    callback(
                        std::make_error_code(std::errc::result_out_of_range),
                        {});
                    return;
                }
                read_key_allowed_ = true;
            }
            size_t length = (read_buffer_[32] << 8) | read_buffer_[33];
            if (length >= 16384) {
                callback(
                    std::make_error_code(std::errc::result_out_of_range), {});
                return;
            }
            read_payload(length, std::move(callback));
        });
}

void EncryptedStream::read_payload(
    size_t length,
    std::function<void(std::error_code, absl::Span<const uint8_t>)> callback) {
    async_read(
        socket_,
        buffer(&read_buffer_[0], length + 16),
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

void EncryptedStream::write_header(
    absl::Span<const uint8_t> chunk,
    std::function<void(std::error_code)> callback) {
    const size_t salt_size = master_key_.method().salt_size;
    RAND_bytes(&write_buffer_[0], salt_size);
    write_key_.emplace(master_key_, &write_buffer_[0]);
    write_length(chunk, salt_size, std::move(callback));
}

void EncryptedStream::write_length(
    absl::Span<const uint8_t> chunk,
    size_t offset,
    std::function<void(std::error_code)> callback) {
    write_buffer_[offset] = static_cast<uint8_t>(chunk.size() >> 8);
    write_buffer_[offset + 1] = static_cast<uint8_t>(chunk.size());
    write_key_->encrypt(
        {&write_buffer_[offset], 2},
        &write_buffer_[offset], &write_buffer_[offset + 2]);
    write_key_->encrypt(
        chunk,
        &write_buffer_[offset + 18],
        &write_buffer_[offset + 18 + chunk.size()]);
    write_payload(offset + chunk.size() + 34, std::move(callback));
}

void EncryptedStream::write_payload(
    size_t size,
    std::function<void(std::error_code)> callback) {
    async_write(
        socket_,
        buffer(&write_buffer_[0], size),
        [callback = std::move(callback)](std::error_code ec, size_t) {
            callback(ec);
        });
}

EncryptedDatagram::EncryptedDatagram(
    udp::socket &socket, const MasterKey &master_key, SaltFilter &salt_filter)
    : socket_(socket),
      master_key_(master_key),
      salt_filter_(salt_filter),
      read_buffer_(std::make_unique<uint8_t[]>(read_buffer_size_)),
      write_buffer_(std::make_unique<uint8_t[]>(write_buffer_size_)) {}

void EncryptedDatagram::receive_from(
    std::function<void(
        std::error_code, absl::Span<const uint8_t>, 
        const udp::endpoint &)> callback) {
    socket_.async_receive_from(
        buffer(read_buffer_.get(), read_buffer_size_), endpoint_,
        [this, callback = std::move(callback)](
            std::error_code ec, size_t size) {
            if (ec) {
                callback(ec, {}, endpoint_);
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
                    {}, endpoint_);
                return;
            }
            if (flags::detect_salt_reuse) {
                if (!salt_filter_.test_and_insert(
                    {&read_buffer_[0], master_key_.method().salt_size})) {
                    callback(
                        std::make_error_code(std::errc::result_out_of_range),
                        {}, endpoint_);
                    return;
                }
            }
            callback({}, {&read_buffer_[salt_size], payload_len}, endpoint_);
        });
}

void EncryptedDatagram::send_to(
    absl::Span<const uint8_t> chunk, const udp::endpoint &endpoint,
    std::function<void(std::error_code)> callback) {
    const size_t salt_size = master_key_.method().salt_size;
    RAND_bytes(write_buffer_.get(), salt_size);
    SessionKey write_key(master_key_, write_buffer_.get());
    write_key.encrypt(
        chunk, &write_buffer_[salt_size],
        &write_buffer_[salt_size + chunk.size()]);
    socket_.async_send_to(
        buffer(write_buffer_.get(), salt_size + chunk.size() + 16), 
        endpoint,
        [this, callback = std::move(callback)](std::error_code ec, size_t) {
            callback(ec);
        });
}

}  // namespace shadowsocks
}  // namespace net
