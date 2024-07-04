load(":cc_toolchain_config.bzl", "cc_toolchain_config")

cc_toolchain_suite(
    name = "toolchain",
    toolchains = {
        "aarch64": ":aarch64_toolchain",
        "k8": ":x86_64_toolchain",  # for bazel compatibility
        "x86_64": ":x86_64_toolchain",
    },
)

filegroup(name = "empty")

cc_toolchain(
    name = "aarch64_toolchain",
    toolchain_identifier = "aarch64-toolchain",
    toolchain_config = ":aarch64_toolchain_config",
    all_files = ":empty",
    compiler_files = ":empty",
    dwp_files = ":empty",
    linker_files = ":empty",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = 0,
)

cc_toolchain_config(
    name = "aarch64_toolchain_config",
    cpu = "aarch64",
    target = "aarch64-linux-gnu",
    dbg_compile_flags = [
        "-g",
        "-fno-omit-frame-pointer",
    ],
    opt_compile_flags = [
        "-g0",
        "-O2",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    link_flags = [
        "-static-libgcc",
        "-l:libstdc++.a",
        "-lm",
    ],
    opt_link_flags = [
        "-Wl,--gc-sections",
    ],
)

cc_toolchain(
    name = "x86_64_toolchain",
    toolchain_identifier = "x86_64-toolchain",
    toolchain_config = ":x86_64_toolchain_config",
    all_files = ":empty",
    compiler_files = ":empty",
    dwp_files = ":empty",
    linker_files = ":empty",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = 0,
)

cc_toolchain_config(
    name = "x86_64_toolchain_config",
    cpu = "x86_64",
    target = "x86_64-linux-gnu",
    dbg_compile_flags = [
        "-g",
        "-fno-omit-frame-pointer",
    ],
    opt_compile_flags = [
        "-g0",
        "-O2",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    link_flags = [
        "-static-libgcc",
        "-l:libstdc++.a",
        "-lm",
    ],
    opt_link_flags = [
        "-Wl,--gc-sections",
    ],
)

platform(
    name = "linux-arm64",
    constraint_values = [
       "@platforms//cpu:arm64",
       "@platforms//os:linux",
    ],
)

platform(
    name = "linux-x86_64",
    constraint_values = [
       "@platforms//cpu:x86_64",
       "@platforms//os:linux",
    ],
)

platform(
    name = "windows-x86_64",
    constraint_values = [
       "@platforms//cpu:x86_64",
       "@platforms//os:windows",
    ],
)
