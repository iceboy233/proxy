package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":handler",
        "//net/proxy:registry",
        "@org_iceboy_trunk//base:logging",
        "@org_boost_boost//:property_tree",
    ],
    alwayslink = 1,
)

cc_library(
    name = "connector",
    srcs = ["connector.cc"],
    hdrs = ["connector.h"],
    deps = [
        ":decryptor",
        ":encryptor",
        ":pre-shared-key",
        "//net/proxy:interface",
        "@com_google_absl//absl/base",
        "@org_iceboy_trunk//net:endpoint",
    ],
)

cc_library(
    name = "decryptor",
    srcs = ["decryptor.cc"],
    hdrs = ["decryptor.h"],
    deps = [
        ":pre-shared-key",
        ":session-subkey",
        "@com_google_absl//absl/container:fixed_array",
        "@org_iceboy_trunk//base:types",
    ],
)

cc_library(
    name = "encryptor",
    srcs = ["encryptor.cc"],
    hdrs = ["encryptor.h"],
    deps = [
        ":pre-shared-key",
        ":session-subkey",
        "@boringssl//:crypto",
        "@org_boost_boost//:endian",
        "@org_iceboy_trunk//base:types",
    ],
)

cc_library(
    name = "handler",
    srcs = ["handler.cc"],
    hdrs = ["handler.h"],
    deps = [
        ":decryptor",
        ":encryptor",
        ":pre-shared-key",
        ":session-subkey",
        "//net/proxy:interface",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:fixed_array",
    ],
)

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
