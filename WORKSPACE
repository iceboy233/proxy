load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository", "new_git_repository")

git_repository(
    name = "boringssl",
    commit = "127d006498acc7c932b85d41d5f4ba3f0cbfbfd6",
    remote = "https://github.com/google/boringssl.git",
)

git_repository(
    name = "com_google_absl",
    commit = "62f05b1f57ad660e9c09e02ce7d591dcc4d0ca08",
    remote = "https://github.com/abseil/abseil-cpp.git",
)

git_repository(
    name = "org_boost_boost",
    commit = "13413ef10592ca33bec6bcadf67f62ced07a1b7f",
    remote = "https://github.com/iceboy233/boost.git",
)

load("@org_boost_boost//:boost_deps.bzl", "boost_deps")
boost_deps()

git_repository(
    name = "org_iceboy_trunk",
    commit = "cea91e3757e4ab227336177d524b842049d8f123",
    remote = "https://github.com/iceboy233/trunk.git",
)
