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

FROM ubuntu:22.04 as final
RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y \
	curl clang-12 bash-completion && ln -s /usr/bin/clang-12 /usr/bin/clang
RUN DEBIAN_FRONTEND=noninteractive apt install -y libelf-dev
RUN curl -Lo /usr/bin/flowctl https://github.com/wide-vsix/linux-flow-exporter/releases/download/branch-main/flowctl.linux-amd64 && chmod +x /usr/bin/flowctl
COPY --from=slankdev/ebpf:dev /usr/sbin/ip /usr/sbin/ss /usr/sbin/tc /usr/sbin/
#COPY --from=builder /usr/sbin/ip /usr/sbin/ss /usr/sbin/tc /usr/sbin/

# COPY --from=builder /usr/sbin/ss /usr/sbin/ss
# COPY --from=builder /usr/sbin/ss /usr/sbin/ss
# COPY --from=builder /usr/sbin/tc /usr/sbin/tc
