package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":connector",
        "//net/proxy",
        "//net/proxy/util:config",
        "@trunk//base:logging",
        "@trunk//net/types:addr-port",
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
        "//net/proxy/ares:resolver",
        "//net/proxy/util:write",
        "@abseil-cpp//absl/strings",
        "@trunk//base:logging",
        "@trunk//net:asio",
        "@trunk//net:timer-list",
        "@trunk//net/interface",
    ],
)

cc_library(
    name = "listener",
    srcs = ["listener.cc"],
    hdrs = ["listener.h"],
    deps = [
        ":tcp-socket-stream",
        ":udp-socket-datagram",
        "@trunk//base:logging",
        "@trunk//net:asio",
        "@trunk//net:timer-list",
        "@trunk//net/interface",
        "@trunk//net/types:addr-port",
    ],
)

cc_library(
    name = "stdio-stream",
    srcs = ["stdio-stream.cc"],
    hdrs = ["stdio-stream.h"],
    deps = [
        "@abseil-cpp//absl/container:fixed_array",
        "@trunk//net:asio",
        "@trunk//net/interface",
    ] + select({
        "@platforms//os:windows": [
            "@trunk//io:file-utils",
            "@trunk//io:native-file",
        ],
        "//conditions:default": [],
    }),
)

cc_library(
    name = "tcp-socket-stream",
    srcs = ["tcp-socket-stream.cc"],
    hdrs = ["tcp-socket-stream.h"],
    deps = [
        "@abseil-cpp//absl/container:fixed_array",
        "@trunk//net:asio",
        "@trunk//net:timer-list",
        "@trunk//net/interface",
    ],
)

cc_library(
    name = "udp-socket-datagram",
    srcs = ["udp-socket-datagram.cc"],
    hdrs = ["udp-socket-datagram.h"],
    deps = [
        "@abseil-cpp//absl/container:fixed_array",
        "@trunk//net:asio",
        "@trunk//net/interface",
    ],
)
