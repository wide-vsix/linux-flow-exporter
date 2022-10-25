ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:3408daa17f6490a464dfc746961e28ae31964c66
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:22.04

# STAGE(llvm-dist)
FROM ${CILIUM_LLVM_IMAGE} as llvm-dist

# STAGE(iproute2-dist)
FROM ${UBUNTU_IMAGE} as iproute2-dist
RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y \
	vim curl git gcc make flex bison clang-12 libbsd-dev libbfd-dev \
	libcap-dev libelf-dev gcc-multilib pkg-config linux-tools-`uname -r`
ARG LIBBPF_VERSION="0.8.0"
ARG IPROUTE2_VERSION="5.18.0"
ADD https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz .
RUN tar xvf v${LIBBPF_VERSION}.tar.gz
RUN cd libbpf-${LIBBPF_VERSION}/src && make install BUILD_STATIC_ONLY=1 && make install_pkgconfig
ADD https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/snapshot/iproute2-${IPROUTE2_VERSION}.tar.gz .
RUN tar xvf iproute2-${IPROUTE2_VERSION}.tar.gz
RUN cd iproute2-${IPROUTE2_VERSION} && ./configure --libbpf_force=on --libbpf_dir=/ && make install

# STAGE(flowctl-dist)
FROM golang:1.17 as flowctl-dist
ARG GIT_SHA=unknown
ARG GIT_BRANCH=unknown
ARG GIT_TAG=unknown
ARG BUILD_DATE=unknown
WORKDIR /opt
COPY ./ ./
RUN CGO_ENABLED=0 go build -o ./bin/flowctl -ldflags "\
  -X github.com/wide-vsix/linux-flow-exporter/pkg/util.gitSHA=$GIT_SHA \
  -X github.com/wide-vsix/linux-flow-exporter/pkg/util.gitBranch=$GIT_BRANCH \
  -X github.com/wide-vsix/linux-flow-exporter/pkg/util.gitTag=$GIT_TAG \
  -X github.com/wide-vsix/linux-flow-exporter/pkg/util.buildDate=$BUILD_DATE \
  " ./cmd/flowctl/main.go

# STAGE(rootfs)
FROM ${UBUNTU_IMAGE} as rootfs
RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y --no-install-recommends \
  curl libelf1 libmnl0 bash-completion iptables ipset kmod ca-certificates \
	libelf-dev libbsd-dev jq
COPY ./bpf /usr/include/bpf
COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=iproute2-dist /usr/sbin/ip /usr/sbin/ss /usr/sbin/tc /usr/sbin/
COPY --from=flowctl-dist /opt/bin/flowctl /usr/bin/
RUN echo "source /etc/bash_completion" >> /root/.bashrc
RUN echo ". <(flowctl completion bash)" >> /root/.bashrc

# FINAL STAGE
FROM scratch
LABEL org.opencontainers.image.source https://github.com/wide-vsix/linux-flow-exporter
COPY --from=rootfs / /
