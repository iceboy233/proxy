package(default_visibility = ["//visibility:public"])

cc_library(
    name = "encryption",
    srcs = ["encryption.cc"],
    hdrs = ["encryption.h"],
    deps = [
        ":hash-filter",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@org_boost_boost//:endian",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
    ],
)

cc_library(
    name = "hash-filter",
    srcs = ["hash-filter.cc"],
    hdrs = ["hash-filter.h"],
    deps = [
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/random",
    ],
)

cc_binary(
    name = "hash-filter_benchmark",
    srcs = ["hash-filter_benchmark.cc"],
    deps = [
        ":hash-filter",
        "@com_google_absl//absl/random",
        "@com_github_google_benchmark//:benchmark_main",
    ],
)

cc_binary(
    name = "hash-filter_stats",
    srcs = ["hash-filter_stats.cc"],
    deps = [
        ":hash-filter",
        "@com_google_absl//absl/random",
    ],
)

cc_test(
    name = "hash-filter_test",
    srcs = ["hash-filter_test.cc"],
    deps = [
        ":hash-filter",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "tcp-server",
    srcs = ["tcp-server.cc"],
    hdrs = ["tcp-server.h"],
    deps = [
        ":encryption",
        ":wire-structs",
        "@com_google_absl//absl/types:span",
        "@org_boost_boost//:smart_ptr",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
    ],
)

cc_library(
    name = "udp-server",
    srcs = ["udp-server.cc"],
    hdrs = ["udp-server.h"],
    deps = [
        ":encryption",
        ":wire-structs",
        "@com_google_absl//absl/types:span",
        "@com_google_absl//absl/container:flat_hash_map",
        "@org_boost_boost//:smart_ptr",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:asio-hash",
    ],
)

cc_library(
    name = "wire-structs",
    hdrs = ["wire-structs.h"],
    deps = [
        "@org_iceboy_trunk//base:packed",
        "@org_iceboy_trunk//net:asio",
    ],
)
