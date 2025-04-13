package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":connector",
        "//net/proxy",
        "//net/proxy/util:config",
        "@trunk//base:logging",
    ],
    alwayslink = 1,
)

cc_library(
    name = "connector",
    srcs = ["connector.cc"],
    hdrs = ["connector.h"],
    deps = [
        ":host-matcher",
        "@trunk//net/interface",
    ],
)

cc_library(
    name = "host-matcher",
    srcs = ["host-matcher.cc"],
    hdrs = ["host-matcher.h"],
    deps = ["@re2"],
)

cc_test(
    name = "host-matcher_test",
    srcs = ["host-matcher_test.cc"],
    deps = [
        ":host-matcher",
        "@googletest//:gtest_main",
    ],
)
