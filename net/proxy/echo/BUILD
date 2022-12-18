package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":handler",
        "//net/proxy:registry",
    ],
    alwayslink = 1,
)

cc_library(
    name = "handler",
    srcs = ["handler.cc"],
    hdrs = ["handler.h"],
    deps = [
        "//net/proxy:interface",
        "@com_google_absl//absl/container:fixed_array",
    ],
)
