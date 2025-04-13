package(default_visibility = ["//visibility:public"])

cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        "@abseil-cpp//absl/container:flat_hash_set",
        "@boost.property_tree",
        "@trunk//base:logging",
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
        "@trunk//net/interface",
    ],
)

cc_library(
    name = "stream-wrapper",
    hdrs = ["stream-wrapper.h"],
    deps = [
        "@trunk//net:asio",
        "@trunk//net/interface",
    ],
)

cc_library(
    name = "write",
    srcs = ["write.cc"],
    hdrs = ["write.h"],
    deps = [
        "@abseil-cpp//absl/functional:any_invocable",
        "@trunk//base:types",
        "@trunk//net/interface",
    ],
)
