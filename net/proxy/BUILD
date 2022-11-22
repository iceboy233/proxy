package(default_visibility = ["//visibility:public"])

cc_library(
    name = "interface",
    hdrs = [
        "connector.h",
        "datagram.h",
        "stream.h",
    ],
    deps = [
        "@com_google_absl//absl/functional:any_invocable",
        "@com_google_absl//absl/types:span",
        "@org_iceboy_trunk//net:asio",
    ]
)
