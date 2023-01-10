package(default_visibility = ["//visibility:public"])

cc_library(
    name = "blake3",
    srcs = [
        "blake3.c",
        "blake3_dispatch.c",
        "blake3_impl.h",
        "blake3_portable.c",
    ] + select({
        ":linux_amd64": [
            "blake3_sse2_x86-64_unix.S",
            "blake3_sse41_x86-64_unix.S",
            "blake3_avx2_x86-64_unix.S",
            "blake3_avx512_x86-64_unix.S",
        ],
        ":linux_arm64": ["blake3_neon.c"],
        ":windows_amd64": [
            "blake3_sse2_x86-64_windows_msvc.asm",
            "blake3_sse41_x86-64_windows_msvc.asm",
            "blake3_avx2_x86-64_windows_msvc.asm",
            "blake3_avx512_x86-64_windows_msvc.asm",
        ],
    }),
    hdrs = ["blake3.h"],
)

# TODO: Move this to a shared place.
# TODO: Make CPU compatible with bazel platforms.
config_setting(
    name = "linux_amd64",
    values = {"cpu": "k8"},
    constraint_values = ["@platforms//os:linux"],
)

config_setting(
    name = "linux_arm64",
    values = {"cpu": "aarch64"},
    constraint_values = ["@platforms//os:linux"],
)

config_setting(
    name = "windows_amd64",
    values = {"cpu": "x64_windows"},
    constraint_values = ["@platforms//os:windows"],
)
