package(default_visibility = ["//visibility:public"])

cc_library(
    name = "proxy",
    srcs = ["proxy.cc"],
    hdrs = ["proxy.h"],
    deps = [
        ":registry",
        "//net/proxy/system:listener",
        "@com_google_absl//absl/container:flat_hash_map",
        "@org_boost_boost//:property_tree",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net/interface",
    ],
)

cc_library(
    name = "registry",
    srcs = ["registry.cc"],
    hdrs = ["registry.h"],
    deps = [
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:any_invocable",
        "@org_boost_boost//:property_tree",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net/interface",
    ],
)
