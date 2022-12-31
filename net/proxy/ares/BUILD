package(default_visibility = ["//visibility:public"])

cc_library(
    name = "resolver",
    srcs = ["resolver.cc"],
    hdrs = ["resolver.h"],
    deps = [
        ":socket",
        "//net/proxy:interface",
        "//third_party/cares",
        "//util:int-allocator",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:any_invocable",
        "@org_iceboy_trunk//net:asio",
    ],
)

cc_library(
    name = "socket",
    srcs = ["socket.cc"],
    hdrs = ["socket.h"],
    deps = [
        "//net/proxy:interface",
        "//third_party/cares",
        "@org_boost_boost//:smart_ptr",
        "@org_iceboy_trunk//net:asio",
    ],
)
