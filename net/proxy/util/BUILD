package(default_visibility = ["//visibility:public"])

cc_library(
    name = "copy",
    srcs = ["copy.cc"],
    hdrs = ["copy.h"],
    deps = [
        ":write",
        "//net/proxy:interface",
        "@com_google_absl//absl/container:fixed_array",
        "@com_google_absl//absl/functional:any_invocable",
    ],
)

cc_library(
    name = "write",
    srcs = ["write.cc"],
    hdrs = ["write.h"],
    deps = [
        "//net/proxy:interface",
        "@com_google_absl//absl/functional:any_invocable",
        "@org_iceboy_trunk//base:types",
    ],
)
