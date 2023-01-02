# Miracle Proxy

Miracle Proxy is a config-based, composable, multi-protocol proxy.

[![Actions Status](https://github.com/iceboy233/proxy/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/iceboy233/proxy/actions/workflows/test.yml)

## Usage

### Getting the binaries

[Releases](https://github.com/iceboy233/proxy/releases)

### Build from source

```
bazel build -c opt net/tools:miracle-proxy
```

The output binary is located at

```
bazel-bin/net/tools/miracle-proxy
```

### Run with config

```
miracle-proxy --config miracle.conf
```

## Config examples

### Socks 5 server

```
listeners {
    "" {
        listen 127.0.0.1:1080
        type socks
    }
}
```

### Shadowsocks server

```
listeners {
    "" {
        listen 0.0.0.0:8388
        type shadowsocks
        method 2022-blake3-aes-128-gcm
        password AAAAAAAAAAAAAAAAAAAAAA
    }
}
```

### Socks 5 server, shadowsocks client (ss-local)

```
listeners {
    "" {
        listen 127.0.0.1:1080
        type socks
        connector proxy
    }
}
connectors {
    proxy {
        type shadowsocks
        server 1.2.3.4:8388
        method 2022-blake3-aes-128-gcm
        password AAAAAAAAAAAAAAAAAAAAAA
    }
}
```
