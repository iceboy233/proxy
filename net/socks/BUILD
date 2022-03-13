package(default_visibility = ["//visibility:public"])

cc_library(
    name = "tcp-server",
    srcs = ["tcp-server.cc"],
    hdrs = ["tcp-server.h"],
    deps = [
        ":wire-structs",
        "@com_google_absl//absl/algorithm",
        "@com_google_absl//absl/strings",
        "@org_boost_boost//:endian",
        "@org_boost_boost//:smart_ptr",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
    ]
)

cc_library(
    name = "wire-structs",
    hdrs = ["wire-structs.h"],
    deps = [
        "@org_iceboy_trunk//base:packed",
        "@org_iceboy_trunk//net:asio",
    ],
)
