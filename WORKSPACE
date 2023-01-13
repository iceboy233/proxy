load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "bazel_skylib",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
    ],
    sha256 = "f7be3474d42aae265405a592bb7da8e171919d74c16f082a5457840f06054728",
)

http_archive(
    name = "boringssl",
    # chromium-107.0.5304.121 (linux/stable)
    sha256 = "e52a66962f40132aaeb17f70218da57e3613e820feb4b15aa05396c1acf543f9",
    strip_prefix = "boringssl-7b00d84b025dff0c392c2df5ee8aa6d3c63ad539",
    urls = ["https://github.com/google/boringssl/archive/7b00d84b025dff0c392c2df5ee8aa6d3c63ad539.zip"],
)

http_archive(
    name = "com_google_absl",
    sha256 = "54707f411cb62a26a776dad5fd60829098c181700edcd022ea5c2ca49e9b7ef1",
    strip_prefix = "abseil-cpp-20220623.1",
    urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.1.zip"],
)

http_archive(
    name = "com_google_googletest",
    sha256 = "24564e3b712d3eb30ac9a85d92f7d720f60cc0173730ac166f27dda7fed76cb2",
    strip_prefix = "googletest-release-1.12.1",
    urls = ["https://github.com/google/googletest/archive/refs/tags/release-1.12.1.zip"],
)

http_archive(
    name = "com_google_re2",
    sha256 = "b9ce3a51beebb38534d11d40f8928d40509b9e18a735f6a4a97ad3d014c87cb5",
    strip_prefix = "re2-d0b1f8f2ecc2ea74956c7608b6f915175314ff0e",
    urls = ["https://github.com/google/re2/archive/d0b1f8f2ecc2ea74956c7608b6f915175314ff0e.zip"],
)

git_repository(
    name = "org_boost_boost",
    commit = "5d277ca0e165c4de02104bb976233cd6c6b7c75f",
    remote = "https://github.com/iceboy233/boost.git",
)

load("@org_boost_boost//:boost_deps.bzl", "boost_deps")
boost_deps()

git_repository(
    name = "org_iceboy_trunk",
    commit = "d15780f227aba09dafd471a9855beeb47e21e070",
    remote = "https://github.com/iceboy233/trunk.git",
)
