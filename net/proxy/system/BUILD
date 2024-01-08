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
        ":tcp-socket-stream",
        ":udp-socket-datagram",
        "//net/proxy:interface",
        "//net/proxy/ares:resolver",
        "@com_google_absl//absl/strings",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:timer-list",
    ],
)

cc_library(
    name = "listener",
    srcs = ["listener.cc"],
    hdrs = ["listener.h"],
    deps = [
        ":tcp-socket-stream",
        ":udp-socket-datagram",
        "//net/proxy:interface",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:endpoint",
        "@org_iceboy_trunk//net:timer-list",
    ],
)

cc_library(
    name = "tcp-socket-stream",
    srcs = ["tcp-socket-stream.cc"],
    hdrs = ["tcp-socket-stream.h"],
    deps = [
        "//net/proxy:interface",
        "@com_google_absl//absl/container:fixed_array",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:timer-list",
    ],
)

cc_library(
    name = "udp-socket-datagram",
    srcs = ["udp-socket-datagram.cc"],
    hdrs = ["udp-socket-datagram.h"],
    deps = [
        "//net/proxy:interface",
        "@com_google_absl//absl/container:fixed_array",
        "@org_iceboy_trunk//net:asio",
    ],
)
