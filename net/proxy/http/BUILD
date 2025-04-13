cc_library(
    name = "h2-connection",
    srcs = ["h2-connection.cc"],
    hdrs = ["h2-connection.h"],
    deps = [
        "//net/proxy/util:write",
        "//third_party/nghttp2",
        "@abseil-cpp//absl/container:fixed_array",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/functional:any_invocable",
        "@abseil-cpp//absl/types:span",
        "@trunk//base:logging",
        "@trunk//net/interface",
        "@trunk//util:strings",
    ],
)

cc_library(
    name = "tls-stream",
    srcs = ["tls-stream.cc"],
    hdrs = ["tls-stream.h"],
    deps = [
        "//net/proxy/util:stream-wrapper",
        "@abseil-cpp//absl/container:fixed_array",
        "@boringssl//:ssl",
        "@trunk//net/interface",
    ],
)
