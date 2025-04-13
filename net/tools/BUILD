cc_binary(
    name = "ares-resolve",
    srcs = ["ares-resolve.cc"],
    deps = [
        "//net/proxy/ares:resolver",
        "//net/proxy/system:connector",
        "@trunk//base:logging",
        "@trunk//io:native-file",
        "@trunk//io:stream",
        "@trunk//net:asio",
        "@trunk//net:blocking-result",
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
        "@trunk//base:flags",
        "@trunk//base:logging",
        "@trunk//net:asio",
        "@trunk//util:strings",
    ],
)
