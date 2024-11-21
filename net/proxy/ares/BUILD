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
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:any_invocable",
        "@com_google_absl//absl/types:span",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:endpoint",
        "@org_iceboy_trunk//net:timer-list",
        "@org_iceboy_trunk//net/interface",
    ],
)

cc_library(
    name = "socket",
    srcs = ["socket.cc"],
    hdrs = ["socket.h"],
    deps = [
        "//net/proxy/util:write",
        "//third_party/cares",
        "@org_boost_boost//:smart_ptr",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net/interface",
    ],
)
