#ifndef _NET_SHADOWSOCKS_ENCRYPTION_H
#define _NET_SHADOWSOCKS_ENCRYPTION_H

#include <openssl/aead.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>
#include <system_error>
#include <boost/endian/arithmetic.hpp>

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
        SaltFilter &salt_filter);

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
        size_t offset,
        std::function<void(std::error_code)> callback);
    void write_payload(
        size_t size,
        std::function<void(std::error_code)> callback);

    tcp::socket &socket_;
    const MasterKey &master_key_;
    SaltFilter &salt_filter_;
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
        SaltFilter &salt_filter);

    void receive_from(
        std::function<void(
            std::error_code, absl::Span<const uint8_t>, 
            const udp::endpoint &)> callback);
    void send_to(
        absl::Span<const uint8_t> chunk, const udp::endpoint &endpoint,
        std::function<void(std::error_code)> callback);

private:
    udp::socket &socket_;
    const MasterKey &master_key_;
    SaltFilter &salt_filter_;
    std::unique_ptr<uint8_t[]> read_buffer_;
    static constexpr size_t read_buffer_size_ = 65535;
    std::unique_ptr<uint8_t[]> write_buffer_;
    static constexpr size_t write_buffer_size_ = 65535;
    udp::endpoint endpoint_;
};

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_ENCRYPTION_H
