load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

# Kitex 端到端链路打点探针。
#
# 这是实验性的侵入式插桩，不适合上游化，故独立成库：
# 插桩点在业务代码里保持一行式，rebase 时容易定位与摘除。
envoy_cc_library(
    name = "kitex_probe_lib",
    srcs = ["probe.cc"],
    hdrs = ["probe.h"],
    deps = [
        "//envoy/common:time_interface",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/strings:str_format",
    ],
)
