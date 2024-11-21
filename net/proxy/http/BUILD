cc_library(
    name = "h2-connection",
    srcs = ["h2-connection.cc"],
    hdrs = ["h2-connection.h"],
    deps = [
        "//net/proxy/util:write",
        "//third_party/nghttp2",
        "@com_google_absl//absl/container:fixed_array",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:any_invocable",
        "@com_google_absl//absl/types:span",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net/interface",
        "@org_iceboy_trunk//util:strings",
    ],
)

cc_library(
    name = "tls-stream",
    srcs = ["tls-stream.cc"],
    hdrs = ["tls-stream.h"],
    deps = [
        "//net/proxy/util:stream-wrapper",
        "@boringssl//:ssl",
        "@com_google_absl//absl/container:fixed_array",
        "@org_iceboy_trunk//net/interface",
    ],
)
