# Miracle Proxy

Miracle Proxy is a config-based proxy that supports multiple protocols and
allows combinations.

## Usage

### Getting the binaries

TODO

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
        endpoint 127.0.0.1:1080
    }
}
handlers {
    "" {
        type socks
    }
}
```

### Shadowsocks server

```
listeners {
    "" {
        endpoint 0.0.0.0:8388
    }
}
handlers {
    "" {
        type shadowsocks
        settings {
            method aes-128-gcm
            password 123456
        }
    }
}
```

### Socks 5 server, shadowsocks client (ss-local)

```
listeners {
    "" {
        endpoint 127.0.0.1:1080
    }
}
handlers {
    "" {
        type socks
        settings {
            connector proxy
        }
    }
}
connectors {
    proxy {
        type shadowsocks
        settings {
            endpoint 1.2.3.4:8388
            method aes-128-gcm
            password 123456
        }
    }
}
```
