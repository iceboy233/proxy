package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":connector",
        ":handler",
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
        ":decryptor",
        ":encryptor",
        ":pre-shared-key",
        ":salt-filter",
        "//net/proxy/util:write",
        "@abseil-cpp//absl/random",
        "@trunk//base:logging",
        "@trunk//net:endpoint",
        "@trunk//net/interface",
    ],
)

cc_library(
    name = "decryptor",
    srcs = ["decryptor.cc"],
    hdrs = ["decryptor.h"],
    deps = [
        ":pre-shared-key",
        ":session-subkey",
        "@abseil-cpp//absl/container:fixed_array",
        "@trunk//base:types",
    ],
)

cc_library(
    name = "encryptor",
    srcs = ["encryptor.cc"],
    hdrs = ["encryptor.h"],
    deps = [
        ":pre-shared-key",
        ":session-subkey",
        "@boost.endian",
        "@boringssl//:crypto",
        "@trunk//base:types",
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
        ":salt-filter",
        ":session-subkey",
        "//net/proxy/util:write",
        "@abseil-cpp//absl/container:fixed_array",
        "@trunk//base:logging",
        "@trunk//net/interface",
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
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "pre-shared-key",
    srcs = ["pre-shared-key.cc"],
    hdrs = ["pre-shared-key.h"],
    deps = [
        ":method",
        "@abseil-cpp//absl/strings",
        "@boringssl//:crypto",
        "@trunk//base:logging",
    ],
)

cc_library(
    name = "salt-filter",
    srcs = ["salt-filter.cc"],
    hdrs = ["salt-filter.h"],
    deps = [
        "@boringssl//:crypto",
        "@trunk//base:types",
        "@trunk//util:hash-filter",
    ],
)

cc_test(
    name = "salt-filter_test",
    srcs = ["salt-filter_test.cc"],
    deps = [
        ":salt-filter",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "session-subkey",
    srcs = ["session-subkey.cc"],
    hdrs = ["session-subkey.h"],
    deps = [
        ":pre-shared-key",
        "//third_party/blake3",
        "@boost.endian",
        "@trunk//base:logging",
        "@trunk//base:types",
    ],
)
