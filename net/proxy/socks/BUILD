package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":handler",
        "//net/proxy",
        "//net/proxy/util:config",
        "@trunk//base:logging",
    ],
    alwayslink = 1,
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
