package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        "@com_google_absl//absl/container:flat_hash_set",
        "@org_boost_boost//:property_tree",
        "@org_iceboy_trunk//base:logging",
    ],
)

cc_library(
    name = "copy",
    srcs = ["copy.cc"],
    hdrs = ["copy.h"],
    deps = [
        ":write",
        "@com_google_absl//absl/container:fixed_array",
        "@com_google_absl//absl/functional:any_invocable",
        "@org_iceboy_trunk//net/interface",
    ],
)

cc_library(
    name = "stream-wrapper",
    hdrs = ["stream-wrapper.h"],
    deps = [
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net/interface",
    ],
)

cc_library(
    name = "write",
    srcs = ["write.cc"],
    hdrs = ["write.h"],
    deps = [
        "@com_google_absl//absl/functional:any_invocable",
        "@org_iceboy_trunk//base:types",
        "@org_iceboy_trunk//net/interface",
    ],
)
