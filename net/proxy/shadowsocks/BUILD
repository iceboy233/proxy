package(default_visibility = ["//visibility:public"])

cc_library(
    name = "method",
    srcs = ["method.cc"],
    hdrs = ["method.h"],
    deps = ["@boringssl//:crypto"],
)

cc_test(
    name = "method_test",
    srcs = ["method_test.cc"],
    deps = [
        ":method",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "pre-shared-key",
    srcs = ["pre-shared-key.cc"],
    hdrs = ["pre-shared-key.h"],
    deps = [
        ":method",
        "@boringssl//:crypto",
    ],
)

cc_library(
    name = "session-subkey",
    srcs = ["session-subkey.cc"],
    hdrs = ["session-subkey.h"],
    deps = [
        ":pre-shared-key",
        "@org_boost_boost//:endian",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//base:types",
    ],
)
