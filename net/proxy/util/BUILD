package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        "@abseil-cpp//absl/container:flat_hash_set",
        "@boost.property_tree",
        "@org_iceboy_trunk//base:logging",
    ],
)

cc_library(
    name = "copy",
    srcs = ["copy.cc"],
    hdrs = ["copy.h"],
    deps = [
        ":write",
        "@abseil-cpp//absl/container:fixed_array",
        "@abseil-cpp//absl/functional:any_invocable",
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
        "@abseil-cpp//absl/functional:any_invocable",
        "@org_iceboy_trunk//base:types",
        "@org_iceboy_trunk//net/interface",
    ],
)
