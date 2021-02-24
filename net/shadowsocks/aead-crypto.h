#ifndef _NET_SHADOWSOCKS_AEAD_CRYPTO_H
#define _NET_SHADOWSOCKS_AEAD_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/aead.h>
#include <array>
#include <functional>
#include <optional>
#include <string_view>
#include <system_error>

#include "absl/types/span.h"
#include "net/asio.h"

namespace net {
namespace shadowsocks {

class AeadCipher {
public:
    AeadCipher(const EVP_AEAD* aead, uint32_t salt_len, uint32_t key_len);
    const EVP_AEAD* aead() const { return aead_; }
    uint32_t salt_len() const {return salt_len_; }
    uint32_t key_len() const { return key_len_; }

private:
    const EVP_AEAD* aead_ = NULL;
    uint32_t salt_len_ = 0;
    uint32_t key_len_ = 0;
};

class AeadMasterKey : public std::array<uint8_t, 32> {
public:
    static AeadMasterKey from_password(
        std::string_view password, uint32_t key_len);
    uint32_t key_len() const { return key_len_; }

private:
    uint32_t key_len_ = 0;
};

class AeadSessionKey {
public:
    AeadSessionKey(
        const AeadMasterKey &master_key, const AeadCipher &cipher, 
        const uint8_t salt[]);
    ~AeadSessionKey();

    void encrypt(
        absl::Span<const uint8_t> in, uint8_t *out, uint8_t out_tag[16]);
    bool decrypt(
        absl::Span<const uint8_t> in, const uint8_t in_tag[16], uint8_t *out);

private:
    EVP_AEAD_CTX aead_ctx_;
    uint64_t nonce_low_ = 0;
    uint32_t nonce_high_ = 0;
};

class AeadStream {
public:
    AeadStream(
        tcp::socket &socket, const AeadCipher &cipher, 
        const AeadMasterKey &master_key);

    void read(
        std::function<void(
            std::error_code, absl::Span<const uint8_t>)> callback);
    void write(
        absl::Span<const uint8_t> chunk,
        std::function<void(std::error_code)> callback);

private:
    void read_header(
        std::function<void(
            std::error_code, absl::Span<const uint8_t>)> callback);
    void read_length(
        std::function<void(
            std::error_code, absl::Span<const uint8_t>)> callback);
    void read_payload(
        size_t length,
        std::function<void(
            std::error_code, absl::Span<const uint8_t>)> callback);
    void write_header(
        absl::Span<const uint8_t> chunk,
        std::function<void(std::error_code)> callback);
    void write_length(
        absl::Span<const uint8_t> chunk,
        std::function<void(std::error_code)> callback);
    void write_payload(
        size_t length,
        std::function<void(std::error_code)> callback);

    tcp::socket &socket_;
    AeadMasterKey master_key_;
    AeadCipher cipher_;
    std::optional<AeadSessionKey> read_key_;
    std::optional<AeadSessionKey> write_key_;
    std::unique_ptr<uint8_t[]> read_buffer_;
    static constexpr size_t read_buffer_size_ = 16384 + 32;
    std::unique_ptr<uint8_t[]> write_buffer_;
    static constexpr size_t write_buffer_size_ = 16384 + 66;
};

class AeadFactory {
public:
    AeadFactory(const AeadCipher &cipher, const AeadMasterKey &master_key);
    std::unique_ptr<AeadStream> new_crypto_stream(
        tcp::socket &socket);
    static std::unique_ptr<AeadFactory> new_from_spec(
        std::string_view cipher, std::string_view password);
        
private:
    AeadCipher cipher_;
    AeadMasterKey master_key_;
};

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_AES_CRYPTO_H
