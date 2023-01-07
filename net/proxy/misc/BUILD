package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":echo-handler",
        ":null-handler",
        ":random-handler",
        ":zero-handler",
        "//net/proxy:registry",
    ],
    alwayslink = 1,
)

cc_library(
    name = "echo-handler",
    srcs = ["echo-handler.cc"],
    hdrs = ["echo-handler.h"],
    deps = [
        "//net/proxy:interface",
        "@com_google_absl//absl/container:fixed_array",
    ],
)

cc_library(
    name = "null-handler",
    srcs = ["null-handler.cc"],
    hdrs = ["null-handler.h"],
    deps = [
        "//net/proxy:interface",
        "@com_google_absl//absl/container:fixed_array",
    ],
)

cc_library(
    name = "random-handler",
    srcs = ["random-handler.cc"],
    hdrs = ["random-handler.h"],
    deps = [
        "//net/proxy:interface",
        "@boringssl//:crypto",
        "@com_google_absl//absl/container:fixed_array",
    ],
)

cc_library(
    name = "zero-handler",
    srcs = ["zero-handler.cc"],
    hdrs = ["zero-handler.h"],
    deps = [
        "//net/proxy:interface",
        "@com_google_absl//absl/container:fixed_array",
    ],
)
