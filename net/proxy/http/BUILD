cc_library(
    name = "h2-connection",
    srcs = ["h2-connection.cc"],
    hdrs = ["h2-connection.h"],
    deps = [
        "//net/proxy:interface",
        "//net/proxy/util:write",
        "//third_party/nghttp2",
        "@com_google_absl//absl/container:fixed_array",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:any_invocable",
        "@com_google_absl//absl/types:span",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//util:strings",
    ],
)
