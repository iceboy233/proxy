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
        "@trunk//net/types:addr-port",
    ],
    alwayslink = 1,
)

cc_library(
    name = "connector",
    srcs = ["connector.cc"],
    hdrs = ["connector.h"],
    deps = [
        "//net/proxy/util:write",
        "@abseil-cpp//absl/base",
        "@trunk//base:logging",
        "@trunk//net/interface",
        "@trunk//net/types:addr-port",
    ],
)

cc_library(
    name = "handler",
    srcs = ["handler.cc"],
    hdrs = ["handler.h"],
    deps = [
        "//net/proxy/util:write",
        "@abseil-cpp//absl/algorithm",
        "@abseil-cpp//absl/container:fixed_array",
        "@boost.endian",
        "@trunk//base:logging",
        "@trunk//base:types",
        "@trunk//net:asio",
        "@trunk//net/interface",
    ],
)
