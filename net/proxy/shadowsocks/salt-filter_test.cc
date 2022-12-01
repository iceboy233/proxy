#include "net/proxy/shadowsocks/salt-filter.h"

#include <gtest/gtest.h>
#include <openssl/rand.h>

namespace net {
namespace proxy {
namespace shadowsocks {
namespace {

TEST(SaltFilterTest, test_and_insert) {
    std::array<uint8_t, 16> salt;
    SaltFilter salt_filter;
    for (int i = 0; i < 1000; ++i) {
        RAND_bytes(salt.data(), salt.size());
        EXPECT_TRUE(salt_filter.test_and_insert(salt));
        EXPECT_FALSE(salt_filter.test_and_insert(salt));
    }
}

}  // namespace
}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
