package(default_visibility = ["//visibility:public"])

cc_library(
    name = "proxy",
    srcs = ["proxy.cc"],
    hdrs = ["proxy.h"],
    deps = [
        ":registry",
        "//net/proxy/system:listener",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@boost.property_tree",
        "@trunk//base:logging",
        "@trunk//net:asio",
        "@trunk//net/interface",
    ],
)

cc_library(
    name = "registry",
    srcs = ["registry.cc"],
    hdrs = ["registry.h"],
    deps = [
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/functional:any_invocable",
        "@boost.property_tree",
        "@trunk//base:logging",
        "@trunk//net:asio",
        "@trunk//net/interface",
    ],
)
