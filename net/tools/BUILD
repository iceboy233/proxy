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
