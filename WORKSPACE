load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository", "new_git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

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

git_repository(
    name = "com_google_absl",
    commit = "215105818dfde3174fe799600bb0f3cae233d0bf",
    remote = "https://github.com/abseil/abseil-cpp.git",
)

git_repository(
    name = "com_google_googletest",
    commit = "e2239ee6043f73722e7aa812a459f54a28552929",
    remote = "https://github.com/google/googletest.git",
)

git_repository(
    name = "org_boost_boost",
    commit = "6ea089e46ba74a7639ba6180a74f63d4d8dfff98",
    remote = "https://github.com/iceboy233/boost.git",
)

load("@org_boost_boost//:boost_deps.bzl", "boost_deps")
boost_deps()

git_repository(
    name = "org_iceboy_trunk",
    commit = "a8f2d2e7fac6ef405b28784fae1d3574febb0b39",
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
