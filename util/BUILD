package(default_visibility = ["//visibility:public"])

cc_library(
    name = "int-allocator",
    hdrs = ["int-allocator.h"],
    deps = ["@com_google_absl//absl/container:btree"],
)

cc_test(
    name = "int-allocator_test",
    srcs = ["int-allocator_test.cc"],
    deps = [
        ":int-allocator",
        "@com_google_googletest//:gtest_main",
    ],
)
