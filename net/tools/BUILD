cc_binary(
    name = "rpc-benchmark",
    srcs = ["rpc-benchmark.cc"],
    deps = [
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:asio-flags",
        "@org_iceboy_trunk//net/rpc:client",
    ],
)

cc_binary(
    name = "rpc-server",
    srcs = ["rpc-server.cc"],
    deps = [
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:asio-flags",
        "@org_iceboy_trunk//net/rpc:server",
    ],
)

cc_binary(
    name = "shadowsocks-server",
    srcs = ["shadowsocks-server.cc"],
    deps = [
        "//net/shadowsocks:encryption",
        "//net/shadowsocks:tcp-server",
        "//net/shadowsocks:udp-server",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:asio-flags",
    ],
)

cc_binary(
    name = "socks-server",
    srcs = ["socks-server.cc"],
    deps = [
        "//net/socks:tcp-server",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:asio-flags",
    ],
)
