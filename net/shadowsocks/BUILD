package(default_visibility = ["//visibility:public"])

cc_library(
    name = "encryption",
    srcs = ["encryption.cc"],
    hdrs = ["encryption.h"],
    deps = [
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
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
    name = "wire-structs",
    hdrs = ["wire-structs.h"],
    deps = [
        "@org_iceboy_trunk//base:packed",
        "@org_iceboy_trunk//net:asio",
    ],
)
