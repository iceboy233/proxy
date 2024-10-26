package(default_visibility = ["//visibility:public"])

cc_library(
    name = "blake3",
    srcs = [
        "blake3.c",
        "blake3_dispatch.c",
        "blake3_impl.h",
        "blake3_portable.c",
    ] + select({
        ":linux_x86_64": [
            "blake3_sse2_x86-64_unix.S",
            "blake3_sse41_x86-64_unix.S",
            "blake3_avx2_x86-64_unix.S",
            "blake3_avx512_x86-64_unix.S",
        ],
        ":linux_aarch64": ["blake3_neon.c"],
        ":windows_x86_64": [
            "blake3_sse2_x86-64_windows_msvc.asm",
            "blake3_sse41_x86-64_windows_msvc.asm",
            "blake3_avx2_x86-64_windows_msvc.asm",
            "blake3_avx512_x86-64_windows_msvc.asm",
        ],
    }),
    hdrs = ["blake3.h"],
)

config_setting(
    name = "linux_x86_64",
    values = {"cpu": "k8"},
    constraint_values = ["@platforms//os:linux"],
)

config_setting(
    name = "linux_aarch64",
    values = {"cpu": "aarch64"},
    constraint_values = ["@platforms//os:linux"],
)

config_setting(
    name = "windows_x86_64",
    values = {"cpu": "x64_windows_msvc"},
    constraint_values = ["@platforms//os:windows"],
)
