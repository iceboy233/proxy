package(default_visibility = ["//visibility:public"])

cc_library(
    name = "blake3",
    srcs = [
        "blake3.c",
        "blake3_dispatch.c",
        "blake3_impl.h",
        "blake3_portable.c",
    ],
    hdrs = ["blake3.h"],
    defines = [
        "BLAKE3_NO_AVX2",
        "BLAKE3_NO_AVX512",
        "BLAKE3_NO_SSE2",
        "BLAKE3_NO_SSE41",
        "BLAKE3_USE_NEON=0",
    ],
)
