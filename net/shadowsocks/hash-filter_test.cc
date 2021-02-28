#include "net/shadowsocks/hash-filter.h"

#include <gtest/gtest.h>

namespace net {
namespace shadowsocks {
namespace {

using testing::Values;

class HashFilterTest : public testing::TestWithParam<uint64_t> {};

TEST_P(HashFilterTest, single) {
    HashFilter filter;
    EXPECT_FALSE(filter.test(GetParam()));
    ASSERT_TRUE(filter.insert(GetParam()));
    EXPECT_TRUE(filter.test(GetParam()));
    filter.clear();
    EXPECT_FALSE(filter.test(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(, HashFilterTest, Values(0, 1, 2, 42));

}  // namespace
}  // namespace shadowsocks
}  // namespace net
