#!/usr/bin/env bash

# Version of libbpf to fetch headers from
LIBBPF_VERSION=1.1.0
# 头文件是直接从libbpf中直接拉取下来的
# vmlinux.h 可以通过bpftool工具生成
# 该头文件包含了所有的内核数据结构，所以就不用依赖安装kernel中的头文件开发包了
# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
# The headers we want
prefix=libbpf-"$LIBBPF_VERSION"
headers=(
    "$prefix"/src/bpf_core_read.h
    "$prefix"/src/bpf_helper_defs.h
    "$prefix"/src/bpf_helpers.h
    "$prefix"/src/bpf_tracing.h
)

# Fetch libbpf release and extract the desired headers
curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" | \
    tar -xz --xform='s#.*/#bpf/#' "${headers[@]}"
