package(default_visibility = ["//visibility:public"])

cc_library(
    name = "error-category",
    srcs = ["error-category.cc"],
    hdrs = ["error-category.h"],
    deps = ["//third_party/cares"],
)

cc_library(
    name = "resolver",
    srcs = ["resolver.cc"],
    hdrs = ["resolver.h"],
    deps = [
        ":error-category",
        ":socket",
        "//third_party/cares",
        "//util:int-allocator",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/functional:any_invocable",
        "@abseil-cpp//absl/types:span",
        "@trunk//net:asio",
        "@trunk//net:timer-list",
        "@trunk//net/interface",
        "@trunk//net/types:addr-port",
    ],
)

cc_library(
    name = "socket",
    srcs = ["socket.cc"],
    hdrs = ["socket.h"],
    deps = [
        "//net/proxy/util:write",
        "//third_party/cares",
        "@boost.smart_ptr",
        "@trunk//net:asio",
        "@trunk//net/interface",
    ],
)
