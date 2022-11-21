package(default_visibility = ["//visibility:public"])

cc_library(
    name = "encryption",
    srcs = ["encryption.cc"],
    hdrs = ["encryption.h"],
    deps = [
        "//net/stream:reader",
        "@boringssl//:crypto",
        "@com_google_absl//absl/types:span",
        "@org_boost_boost//:container",
        "@org_boost_boost//:endian",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//util:hash-filter",
    ],
)

cc_library(
    name = "tcp-server",
    srcs = ["tcp-server.cc"],
    hdrs = ["tcp-server.h"],
    deps = [
        ":encryption",
        ":wire-structs",
        "//net/proxy:interface",
        "@com_google_absl//absl/types:span",
        "@com_google_absl//absl/strings",
        "@org_boost_boost//:endian",
        "@org_boost_boost//:smart_ptr",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:rate-limiter",
        "@org_iceboy_trunk//net:timer-list",
    ],
)

cc_library(
    name = "udp-server",
    srcs = ["udp-server.cc"],
    hdrs = ["udp-server.h"],
    deps = [
        ":encryption",
        ":wire-structs",
        "//net/proxy:interface",
        "@com_google_absl//absl/types:span",
        "@com_google_absl//absl/container:flat_hash_map",
        "@org_boost_boost//:endian",
        "@org_boost_boost//:smart_ptr",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:asio-hash",
        "@org_iceboy_trunk//net:rate-limiter",
        "@org_iceboy_trunk//net:timer-list",
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
