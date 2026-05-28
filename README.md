# Proxy

[![Test](https://github.com/iceboy233/proxy/actions/workflows/test.yml/badge.svg)](https://github.com/iceboy233/proxy/actions/workflows/test.yml)

A config-based, composable, multi-protocol proxy.

Note: Proxy is now implemented with Rust. There should be a previous C++
implementation in the
[legacy-cpp](https://github.com/iceboy233/proxy/tree/legacy-cpp) branch.

## Getting started

You can get pre-built binaries from the
[Releases](https://github.com/iceboy233/proxy/releases) page.

To build from source, make sure you have Rust stable and Cargo installed.

```
cargo build --release
```

To run the proxy:

```
target/release/proxy --config examples/socks-server.toml
```

See [examples](examples) directory for some example configurations.

## License

This project is licensed under the MIT NON-AI License. See the LICENSE file for
details.
