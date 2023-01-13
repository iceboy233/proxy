package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":connector",
        "//net/proxy",
        "@org_boost_boost//:property_tree",
        "@org_iceboy_trunk//base:logging",
    ],
    alwayslink = 1,
)

cc_library(
    name = "connector",
    srcs = ["connector.cc"],
    hdrs = ["connector.h"],
    deps = [
        ":host-matcher",
        "//net/proxy:interface",
    ],
)

cc_library(
    name = "host-matcher",
    srcs = ["host-matcher.cc"],
    hdrs = ["host-matcher.h"],
    deps = ["@com_google_re2//:re2"],
)

cc_test(
    name = "host-matcher_test",
    srcs = ["host-matcher_test.cc"],
    deps = [
        ":host-matcher",
        "@com_google_googletest//:gtest_main",
    ],
)
