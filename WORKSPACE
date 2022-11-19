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

git_repository(
    name = "boringssl",
    commit = "f9eff21461cf79556a0fb8ca9b1bf60c3b283ce8",
    remote = "https://github.com/google/boringssl.git",
)

git_repository(
    name = "com_github_google_benchmark",
    commit = "0d98dba29d66e93259db7daa53a9327df767a415",
    remote = "https://github.com/google/benchmark.git",
)

git_repository(
    name = "com_github_google_flatbuffers",
    commit = "a9a295fecf3fbd5a4f571f53b01f63202a3e2113",
    remote = "https://github.com/google/flatbuffers.git",
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

git_repository(
    name = "org_boost_boost",
    commit = "60a48497f5f9453049e8a35b8f0c799d2673e9e5",
    remote = "https://github.com/iceboy233/boost.git",
)

load("@org_boost_boost//:boost_deps.bzl", "boost_deps")
boost_deps()

git_repository(
    name = "org_iceboy_trunk",
    commit = "d1d2665a3308ab50b460b6a14483a91c16f3c3e6",
    remote = "https://github.com/iceboy233/trunk.git",
)

http_archive(
    name = "murtis_bazel_compilers",
    urls = [
        "https://github.com/curtismuntz/bazel_compilers/archive/e7c3ee9820bfde7f7284bbc3a9540293741719cd.tar.gz",
    ],
    strip_prefix = "bazel_compilers-e7c3ee9820bfde7f7284bbc3a9540293741719cd",
)

load("@murtis_bazel_compilers//compilers:dependencies.bzl", "cross_compiler_dependencies")

cross_compiler_dependencies()
