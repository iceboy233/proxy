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
}

TEST(MethodTest, aes_192_gcm) {
    const auto &method = *Method::find("aes-192-gcm");
    EXPECT_EQ(method.key_size(), 24);
    EXPECT_EQ(method.salt_size(), 24);
    EXPECT_EQ(method.nonce_size(), 12);
}

TEST(MethodTest, aes_256_gcm) {
    const auto &method = *Method::find("aes-256-gcm");
    EXPECT_EQ(method.key_size(), 32);
    EXPECT_EQ(method.salt_size(), 32);
    EXPECT_EQ(method.nonce_size(), 12);
}

TEST(MethodTest, chacha20_ietf_poly1305) {
    const auto &method = *Method::find("chacha20-ietf-poly1305");
    EXPECT_EQ(method.key_size(), 32);
    EXPECT_EQ(method.salt_size(), 32);
    EXPECT_EQ(method.nonce_size(), 12);
}

TEST(MethodTest, xchacha20_ietf_poly1305) {
    const auto &method = *Method::find("xchacha20-ietf-poly1305");
    EXPECT_EQ(method.key_size(), 32);
    EXPECT_EQ(method.salt_size(), 32);
    EXPECT_EQ(method.nonce_size(), 24);
}

}  // namespace
}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
