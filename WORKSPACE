load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "bazel_skylib",
    urls = ["https://github.com/bazelbuild/bazel-skylib/releases/download/1.5.0/bazel-skylib-1.5.0.tar.gz"],
    integrity = "sha256-zVWgYudjuTSZIfD124w5MyiNyLpPdt2UFqrGis7jy5Q=",
)

http_archive(
    name = "boringssl",
    # 0.0.0-20240126-22d349c
    urls = ["https://github.com/google/boringssl/archive/22d349c4596e81425ec88f82fab47063a9a2bac6.tar.gz"],
    integrity = "sha256-rMEdcuN6QX90hSzHXUCE7HEhcnwBvR6bVSUjHJsDwnc=",
    strip_prefix = "boringssl-22d349c4596e81425ec88f82fab47063a9a2bac6",
)

http_archive(
    name = "com_google_absl",
    urls = ["https://github.com/abseil/abseil-cpp/releases/download/20240116.2/abseil-cpp-20240116.2.tar.gz"],
    integrity = "sha256-czcmuMOm05pBINfkXqi0GkNM2s3kAculAPFCNsSbOdw=",
    strip_prefix = "abseil-cpp-20240116.2",
)

http_archive(
    name = "com_google_googletest",
    urls = ["https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz"],
    integrity = "sha256-itWYxzrXluDYKAsILOvYKmMNc+c808cAV5OKZQG7pdc=",
    strip_prefix = "googletest-1.14.0",
)

http_archive(
    name = "com_google_re2",
    urls = ["https://github.com/google/re2/releases/download/2023-09-01/re2-2023-09-01.zip"],
    integrity = "sha256-IkuDUdxGM7EBLb2EdWTgYKRr5goioUY9S1uZP9S/Wcw=",
    strip_prefix = "re2-2023-09-01",
)

git_repository(
    name = "org_boost_boost",
    commit = "2a72734ebe29e1c2abcf5b84443e385b20071e8d",
    remote = "https://github.com/iceboy233/boost.git",
)

load("@org_boost_boost//:boost_deps.bzl", "boost_deps")
boost_deps()

git_repository(
    name = "org_iceboy_trunk",
    commit = "0be2a93fa780f608f8bfffa48a5e0367a5c08605",
    remote = "https://github.com/iceboy233/trunk.git",
)
