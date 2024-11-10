package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":handler",
        "//net/proxy",
        "//net/proxy/util:config",
        "@org_iceboy_trunk//base:logging",
    ],
    alwayslink = 1,
)

cc_library(
    name = "handler",
    srcs = ["handler.cc"],
    hdrs = ["handler.h"],
    deps = [
        "//net/proxy:interface",
        "//net/proxy/util:write",
        "@com_google_absl//absl/algorithm",
        "@com_google_absl//absl/container:fixed_array",
        "@org_boost_boost//:endian",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//base:types",
        "@org_iceboy_trunk//net:asio",
    ],
)
