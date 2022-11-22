package(default_visibility = ["//visibility:public"])

cc_library(
    name = "connector",
    srcs = ["connector.cc"],
    hdrs = ["connector.h"],
    deps = [
        "//net/proxy:interface",
        "@com_google_absl//absl/container:fixed_array",
        "@com_google_absl//absl/strings",
        "@org_iceboy_trunk//net:asio",
    ],
)
