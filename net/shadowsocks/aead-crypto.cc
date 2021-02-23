#include "net/shadowsocks/aead-crypto.h"

#include <stdlib.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

#include "base/logging.h"

namespace net {
namespace shadowsocks {

struct aead_cipher_entry {
    const char      *name;
    const EVP_AEAD  *cipher;
    uint32_t        key_len;
};

static aead_cipher_entry aead_cipher_entries[] =
{
    { .name = "aes-128-gcm",            .cipher = EVP_aead_aes_128_gcm(),
        .key_len = 16 },
    { .name = "aes-192-gcm",            .cipher = EVP_aead_aes_192_gcm(),
        .key_len = 24 },
    { .name = "aes-256-gcm",            .cipher = EVP_aead_aes_256_gcm(),
        .key_len = 32 },
    { .name = "chacha20-ietf-poly1305", .cipher = EVP_aead_chacha20_poly1305(),
        .key_len = 32 },
    {}
};

AeadMasterKey AeadMasterKey::from_password(std::string_view password, 
    const char* cipher_name) {
    AeadMasterKey key;
    MD5_CTX ctx;
    uint8_t digest[16];
    bool addmd = false;
    uint32_t key_len = 0;
    for (int i = 0; aead_cipher_entries[i].name; i++) {
        if (!strcmp(aead_cipher_entries[i].name, cipher_name)) {
            key_len = aead_cipher_entries[i].key_len;
            key.cipher_ = aead_cipher_entries[i].cipher;
            key.key_len_ = key_len;
        }
    }
    if (!key_len){
        LOG(fatal) << "Encrypt method '" << cipher_name << "' not supported";
        abort();
    }
    for (uint32_t key_pos = 0; key_pos < key_len; addmd = true) {
        MD5_Init(&ctx);
        if (addmd) {
            MD5_Update(&ctx, digest, 16);
        }
        MD5_Update(&ctx, password.data(), password.size());
        MD5_Final(digest, &ctx);
        for (uint32_t i = 0; i < 16; i++, key_pos++) {
            if (key_pos >= key_len)
                break;
            key[key_pos] = digest[i];
        }
    }
    return key;
}

AeadSessionKey::AeadSessionKey(
    const AeadMasterKey &master_key, const uint8_t salt[]) {
    std::array<uint8_t, 32> key;
    salt_len_ = master_key.key_len();
    if (!HKDF(
        key.data(), master_key.key_len(), EVP_sha1(),
        master_key.data(), master_key.key_len(), salt, salt_len_,
        reinterpret_cast<const uint8_t *>("ss-subkey"), 9)) {
        LOG(fatal) << "HKDF failed";
        abort();
    }
    if (!EVP_AEAD_CTX_init(
        &aead_ctx_, master_key.cipher(), key.data(), master_key.key_len(), 
        16, nullptr)) {
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
        buffer(read_buffer_.get(), master_key_.key_len()),
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
    uint32_t salt_len = master_key_.key_len();
    RAND_bytes(write_buffer_.get(), salt_len);
    write_key_.emplace(master_key_, write_buffer_.get());
    write_buffer_[salt_len] = static_cast<uint8_t>(chunk.size() >> 8);
    write_buffer_[salt_len + 1] = static_cast<uint8_t>(chunk.size());
    write_key_->encrypt(
        {&write_buffer_[salt_len], 2}, 
        &write_buffer_[salt_len],       // salt
        &write_buffer_[salt_len + 2]);  // salt + len
    write_key_->encrypt(
        chunk, 
        &write_buffer_[salt_len + 18],  // salt + len + tag
        &write_buffer_[salt_len + 18 + chunk.size()]);
    write_payload(chunk.size() + salt_len + 34, std::move(callback));
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
