cc_binary(
    name = "ares-resolve",
    srcs = ["ares-resolve.cc"],
    deps = [
        "//net/proxy/ares:resolver",
        "//net/proxy/system:connector",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//io:native-file",
        "@org_iceboy_trunk//io:stream",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//net:blocking-result",
    ],
)

cc_binary(
    name = "miracle-proxy",
    srcs = ["miracle-proxy.cc"],
    deps = [
        "//net/proxy",
        "//net/proxy/misc:config",
        "//net/proxy/route:config",
        "//net/proxy/shadowsocks:config",
        "//net/proxy/socks:config",
        "//net/proxy/system:config",
        "//net/proxy/system:stdio-stream",
        "//net/proxy/util:copy",
        "@boost.property_tree",
        "@org_iceboy_trunk//base:flags",
        "@org_iceboy_trunk//base:logging",
        "@org_iceboy_trunk//net:asio",
        "@org_iceboy_trunk//util:strings",
    ],
)
