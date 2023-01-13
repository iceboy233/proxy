#include "net/proxy/route/host-matcher.h"

#include <gtest/gtest.h>

namespace net {
namespace proxy {
namespace route {
namespace {

TEST(HostMatcherTest, match_host) {
    HostMatcher matcher;
    ASSERT_EQ(matcher.add("www.apple.com"), 0);
    ASSERT_EQ(matcher.add("www.banana.com"), 1);
    matcher.build();
    EXPECT_EQ(matcher.match("www.apple.com"), 0);
    EXPECT_EQ(matcher.match("www.banana.com"), 1);
    EXPECT_EQ(matcher.match("www.orange.com"), -1);
    EXPECT_EQ(matcher.match("apple.com"), -1);
    EXPECT_EQ(matcher.match("wwwwapple.com"), -1);
    EXPECT_EQ(matcher.match("wwww.apple.com"), -1);
    EXPECT_EQ(matcher.match("www.apple.co"), -1);
    EXPECT_EQ(matcher.match("www.apple.comm"), -1);
}

TEST(HostMatcherTest, match_host_suffix) {
    HostMatcher matcher;
    ASSERT_EQ(matcher.add_suffix("apple.com"), 0);
    ASSERT_EQ(matcher.add_suffix("banana.com"), 1);
    matcher.build();
    EXPECT_EQ(matcher.match("apple.com"), 0);
    EXPECT_EQ(matcher.match("banana.com"), 1);
    EXPECT_EQ(matcher.match("orange.com"), -1);
    EXPECT_EQ(matcher.match("www.apple.com"), 0);
    EXPECT_EQ(matcher.match("www.banana.com"), 1);
    EXPECT_EQ(matcher.match("appleecom"), -1);
    EXPECT_EQ(matcher.match("aapple.com"), -1);
    EXPECT_EQ(matcher.match("apple.co"), -1);
    EXPECT_EQ(matcher.match("apple.comm"), -1);
}

}  // namespace
}  // namespace route
}  // namespace proxy
}  // namespace net
