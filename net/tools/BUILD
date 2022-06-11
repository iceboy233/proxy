cc_binary(
    name = "http-server",
    srcs = ["http-server.cc"],
    deps = [
        "//net:endpoint",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net/http:server",
    ],
)

cc_binary(
    name = "rpc-benchmark",
    srcs = ["rpc-benchmark.cc"],
    deps = [
        "//net:endpoint",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net/rpc:client",
    ],
)

cc_binary(
    name = "rpc-relay",
    srcs = ["rpc-relay.cc"],
    deps = [
        "//net:endpoint",
        "@com_google_absl//absl/strings",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net/rpc:client",
        "@org_iceboy_trunk//net/rpc:server",
        "@org_iceboy_trunk//security:key",
    ],
)

cc_binary(
    name = "rpc-server",
    srcs = ["rpc-server.cc"],
    deps = [
        "//net:endpoint",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net/rpc:server",
    ],
)

cc_binary(
    name = "shadowsocks-server",
    srcs = ["shadowsocks-server.cc"],
    deps = [
        "//net:endpoint",
        "//net/shadowsocks:encryption",
        "//net/shadowsocks:tcp-server",
        "//net/shadowsocks:udp-server",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
    ],
)

cc_binary(
    name = "socks-server",
    srcs = ["socks-server.cc"],
    deps = [
        "//net:endpoint",
        "//net/socks:tcp-server",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
    ],
)
