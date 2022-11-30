#include "net/proxy/shadowsocks/method.h"

#include <gtest/gtest.h>

namespace net {
namespace proxy {
namespace shadowsocks {
namespace {

TEST(MethodTest, aes_128_gcm) {
    const auto &method = *Method::find("aes-128-gcm");
    EXPECT_EQ(method.key_size(), 16);
    EXPECT_EQ(method.salt_size(), 16);
    EXPECT_EQ(method.nonce_size(), 12);
    EXPECT_EQ(method.max_chunk_size(), 16383);
    EXPECT_EQ(method.is_spec_2022(), false);
}

TEST(MethodTest, aes_192_gcm) {
    const auto &method = *Method::find("aes-192-gcm");
    EXPECT_EQ(method.key_size(), 24);
    EXPECT_EQ(method.salt_size(), 24);
    EXPECT_EQ(method.nonce_size(), 12);
    EXPECT_EQ(method.max_chunk_size(), 16383);
    EXPECT_EQ(method.is_spec_2022(), false);
}

TEST(MethodTest, aes_256_gcm) {
    const auto &method = *Method::find("aes-256-gcm");
    EXPECT_EQ(method.key_size(), 32);
    EXPECT_EQ(method.salt_size(), 32);
    EXPECT_EQ(method.nonce_size(), 12);
    EXPECT_EQ(method.max_chunk_size(), 16383);
    EXPECT_EQ(method.is_spec_2022(), false);
}

TEST(MethodTest, chacha20_ietf_poly1305) {
    const auto &method = *Method::find("chacha20-ietf-poly1305");
    EXPECT_EQ(method.key_size(), 32);
    EXPECT_EQ(method.salt_size(), 32);
    EXPECT_EQ(method.nonce_size(), 12);
    EXPECT_EQ(method.max_chunk_size(), 16383);
    EXPECT_EQ(method.is_spec_2022(), false);
}

TEST(MethodTest, xchacha20_ietf_poly1305) {
    const auto &method = *Method::find("xchacha20-ietf-poly1305");
    EXPECT_EQ(method.key_size(), 32);
    EXPECT_EQ(method.salt_size(), 32);
    EXPECT_EQ(method.nonce_size(), 24);
    EXPECT_EQ(method.max_chunk_size(), 16383);
    EXPECT_EQ(method.is_spec_2022(), false);
}

TEST(MethodTest, _2022_blake3_aes_128_gcm) {
    const auto &method = *Method::find("2022-blake3-aes-128-gcm");
    EXPECT_EQ(method.key_size(), 16);
    EXPECT_EQ(method.salt_size(), 16);
    EXPECT_EQ(method.nonce_size(), 12);
    EXPECT_EQ(method.max_chunk_size(), 65535);
    EXPECT_EQ(method.is_spec_2022(), true);
}

TEST(MethodTest, _2022_blake3_aes_192_gcm) {
    const auto &method = *Method::find("2022-blake3-aes-192-gcm");
    EXPECT_EQ(method.key_size(), 24);
    EXPECT_EQ(method.salt_size(), 24);
    EXPECT_EQ(method.nonce_size(), 12);
    EXPECT_EQ(method.max_chunk_size(), 65535);
    EXPECT_EQ(method.is_spec_2022(), true);
}

TEST(MethodTest, _2022_blake3_aes_256_gcm) {
    const auto &method = *Method::find("2022-blake3-aes-256-gcm");
    EXPECT_EQ(method.key_size(), 32);
    EXPECT_EQ(method.salt_size(), 32);
    EXPECT_EQ(method.nonce_size(), 12);
    EXPECT_EQ(method.max_chunk_size(), 65535);
    EXPECT_EQ(method.is_spec_2022(), true);
}

TEST(MethodTest, _2022_blake3_chacha20_poly1305) {
    const auto &method = *Method::find("2022-blake3-chacha20-poly1305");
    EXPECT_EQ(method.key_size(), 32);
    EXPECT_EQ(method.salt_size(), 32);
    EXPECT_EQ(method.nonce_size(), 12);
    EXPECT_EQ(method.max_chunk_size(), 65535);
    EXPECT_EQ(method.is_spec_2022(), true);
}

TEST(MethodTest, _2022_blake3_xchacha20_poly1305) {
    const auto &method = *Method::find("2022-blake3-xchacha20-poly1305");
    EXPECT_EQ(method.key_size(), 32);
    EXPECT_EQ(method.salt_size(), 32);
    EXPECT_EQ(method.nonce_size(), 24);
    EXPECT_EQ(method.max_chunk_size(), 65535);
    EXPECT_EQ(method.is_spec_2022(), true);
}

}  // namespace
}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
