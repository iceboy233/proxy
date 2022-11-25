package(default_visibility = ["//visibility:public"])

cc_library(
    name = "interface",
    hdrs = [
        "connector.h",
        "datagram.h",
        "handler.h",
        "stream.h",
    ],
    deps = [
        "@com_google_absl//absl/functional:any_invocable",
        "@com_google_absl//absl/types:span",
        "@org_iceboy_trunk//net:asio",
    ]
)

cc_library(
    name = "proxy",
    srcs = ["proxy.cc"],
    hdrs = ["proxy.h"],
    deps = [
        ":interface",
        ":registry",
        "//net/proxy/system:listener",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:bind_front",
        "@org_boost_boost//:property_tree",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
    ],
)

cc_library(
    name = "registry",
    srcs = ["registry.cc"],
    hdrs = ["registry.h"],
    deps = [
        ":interface",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:any_invocable",
        "@org_boost_boost//:property_tree",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
    ],
)
