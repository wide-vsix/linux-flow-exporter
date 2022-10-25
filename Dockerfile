# FROM ubuntu:22.04 as builder
# ARG LIBBPF_VERSION="0.8.0"
# ARG IPROUTE2_VERSION="5.18.0"
# #ARG BPFTOOL_VERSION="6.8.0"
# 
# RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y \
# 	vim curl git gcc make flex bison clang-12 libbsd-dev libbfd-dev \
# 	libcap-dev libelf-dev gcc-multilib pkg-config linux-tools-`uname -r`
# RUN ln -s /usr/bin/clang-12 /usr/bin/clang
# 
# WORKDIR /opt
# 
# ADD https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz .
# RUN tar xvf v${LIBBPF_VERSION}.tar.gz
# RUN cd libbpf-${LIBBPF_VERSION}/src && make install BUILD_STATIC_ONLY=1 && make install_pkgconfig
# #RUN rm -rf libbpf-${LIBBPF_VERSION} v${LIBBPF_VERSION}.tar.gz
# 
# ADD https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/snapshot/iproute2-${IPROUTE2_VERSION}.tar.gz .
# RUN tar xvf iproute2-${IPROUTE2_VERSION}.tar.gz
# RUN cd iproute2-${IPROUTE2_VERSION} && ./configure --libbpf_force=on --libbpf_dir=/ && make install
#RUN rm -rf iproute2-${IPROUTE2_VERSION} iproute2-${IPROUTE2_VERSION}.tar.gz

# FROM ubuntu:22.04 as final
# RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y \
# 	curl clang-12 bash-completion && ln -s /usr/bin/clang-12 /usr/bin/clang
# RUN DEBIAN_FRONTEND=noninteractive apt install -y libelf-dev
# RUN curl -Lo /usr/bin/flowctl https://github.com/wide-vsix/linux-flow-exporter/releases/download/branch-main/flowctl.linux-amd64 && chmod +x /usr/bin/flowctl
# COPY --from=slankdev/ebpf:dev /usr/sbin/ip /usr/sbin/ss /usr/sbin/tc /usr/sbin/
#COPY --from=builder /usr/sbin/ip /usr/sbin/ss /usr/sbin/tc /usr/sbin/

# COPY --from=builder /usr/sbin/ss /usr/sbin/ss
# COPY --from=builder /usr/sbin/ss /usr/sbin/ss
# COPY --from=builder /usr/sbin/tc /usr/sbin/tc

# syntax=docker/dockerfile:1.2

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG UBUNTU_IMAGE=docker.io/library/ubuntu:22.04@sha256:26c68657ccce2cb0a31b330cb0be2b5e108d467f641c62e13ab40cbec258c68d
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:3408daa17f6490a464dfc746961e28ae31964c66@sha256:ff13a1a9f973d102c6ac907d2bc38a524c8e1d26c6c1b16ed809a98925206a79
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:d3093f6aeefef8270306011109be623a7e80ad1b@sha256:2c28c64195dee20ab596d70a59a4597a11058333c6b35a99da32c339dcd7df56
ARG CILIUM_IPROUTE2_IMAGE=quay.io/cilium/cilium-iproute2:f882e3fd516184703eea5ee9b3b915748b5d4ee8@sha256:f22b8aaf01952cf4b2ec959f0b8f4d242b95ce279480fbd73fded606ce0c3fa4

FROM ${CILIUM_LLVM_IMAGE} as llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} as bpftool-dist
FROM ${CILIUM_IPROUTE2_IMAGE} as iproute2-dist
RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu

FROM ${UBUNTU_IMAGE} as rootfs

# Change the number to force the generation of a new git-tree SHA. Useful when
# we want to re-run 'apt-get upgrade' for stale images.
ENV FORCE_BUILD=2
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y jq
COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local /usr/local/
#COPY --from=slankdev/ebpf:dev /usr/sbin/ip /usr/sbin/ss /usr/sbin/tc /usr/sbin/
COPY --from=iproute2-dist /usr/lib/libbpf* /usr/lib/
COPY --from=iproute2-dist /usr/local /usr/local/

#RUN apt install -y curl libelf-dev

RUN apt install -y --no-install-recommends \
  curl \
  libelf1 \
  libmnl0 \
  bash-completion \
  iptables \
  ipset \
  kmod \
  ca-certificates

RUN curl -Lo /usr/bin/flowctl https://github.com/wide-vsix/linux-flow-exporter/releases/download/branch-main/flowctl.linux-amd64 && chmod +x /usr/bin/flowctl

# FROM scratch
# LABEL maintainer="maintainer@cilium.io"
# COPY --from=rootfs / /
