package(default_visibility = ["//visibility:public"])

cc_library(
    name = "interface",
    hdrs = [
        "connector.h",
        "stream.h",
    ],
    deps = [
        "@com_google_absl//absl/container:fixed_array",
        "@com_google_absl//absl/functional:any_invocable",
        "@org_iceboy_trunk//net:asio",
    ]
)

cc_library(
    name = "system",
    srcs = ["system.cc"],
    hdrs = ["system.h"],
    deps = [
        ":interface",
        "@com_google_absl//absl/strings",
        "@org_iceboy_trunk//net:asio",
    ],
)
