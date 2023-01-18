#include "net/proxy/route/host-matcher.h"

#include <gtest/gtest.h>

namespace net {
namespace proxy {
namespace route {
namespace {

TEST(HostMatcherTest, match_host) {
    HostMatcher matcher;
    matcher.add("www.apple.com", 100);
    matcher.add("www.banana.com", 101);
    matcher.build();
    EXPECT_EQ(matcher.match("www.apple.com"), 100);
    EXPECT_EQ(matcher.match("www.banana.com"), 101);
    EXPECT_FALSE(matcher.match("www.orange.com"));
    EXPECT_FALSE(matcher.match("apple.com"));
    EXPECT_FALSE(matcher.match("wwwwapple.com"));
    EXPECT_FALSE(matcher.match("wwww.apple.com"));
    EXPECT_FALSE(matcher.match("www.apple.co"));
    EXPECT_FALSE(matcher.match("www.apple.comm"));
}

TEST(HostMatcherTest, match_host_suffix) {
    HostMatcher matcher;
    matcher.add_suffix("apple.com", 100);
    matcher.add_suffix("banana.com", 101);
    matcher.build();
    EXPECT_EQ(matcher.match("apple.com"), 100);
    EXPECT_EQ(matcher.match("banana.com"), 101);
    EXPECT_FALSE(matcher.match("orange.com"));
    EXPECT_EQ(matcher.match("www.apple.com"), 100);
    EXPECT_EQ(matcher.match("www.banana.com"), 101);
    EXPECT_FALSE(matcher.match("appleecom"));
    EXPECT_FALSE(matcher.match("aapple.com"));
    EXPECT_FALSE(matcher.match("apple.co"));
    EXPECT_FALSE(matcher.match("apple.comm"));
}

}  // namespace
}  // namespace route
}  // namespace proxy
}  // namespace net
