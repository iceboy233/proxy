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
    name = "com_github_google_benchmark",
    commit = "c5b2fe9357b3862b7f99b94d7999002dcf269faf",
    remote = "https://github.com/google/benchmark.git",
)

git_repository(
    name = "com_google_googletest",
    commit = "dcc92d0ab6c4ce022162a23566d44f673251eee4",
    remote = "https://github.com/google/googletest.git",
)

git_repository(
    name = "org_boost_boost",
    commit = "30dd3a31d48c29b149dc066a1a38e67db0bdbc5d",
    remote = "https://github.com/iceboy233/boost.git",
)

load("@org_boost_boost//:boost_deps.bzl", "boost_deps")
boost_deps()

git_repository(
    name = "org_iceboy_trunk",
    commit = "151a6069bacb4e7a7aa08d84646e38f47eccfc53",
    remote = "https://github.com/iceboy233/trunk.git",
)
