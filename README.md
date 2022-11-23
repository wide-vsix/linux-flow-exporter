# linux-flow-exporter

eBPF based IPFIX exporter. This software is an IPFIX flow-exporter for routing
with Linux kernel. It records flow stats forwarded by the kernel using tc-ebpf,
without AF_PACKET or conntrack. Some flow-exporter using AF_PACKET has
performance issues due to frequent user/kernel communication, and Some one using
conntrack does not work properly in a multipath environment. This software is an
flow-exporter that does not have such issues and supports multipath environment
with less performance issues.

## System Components

- ebpflow: in-kernel flow-stats collector with ebpf
- flowctl: user-space cli utility includes:
  - daemonized agent for IPFIX flow-exporter
  - dump the in-kernel flow-stats from the user-space
  - IPFIX dummy data transmitter for test
- dependencies (tested)
  - linux kernel 5.x+
  - iproute2 5.18+

Requirements: you can verifiy compatibity with `dependency-check` subcmd.
- `clang --version`: 10.0.0
- `uname -r`: 5.15.0-1008-gcp
- `ip -V`: ip utility, iproute2-5.18.0, libbpf 0.8.0
  - iproute2 is needed to attach ebpf program into the kernel.

```
$ sudo flowctl dependency-check
clang version (expect v10.0.0): v12.0.1 (VALID)
kernel version (expect v5.4.0): v5.15.0 (VALID)
iproute2 binary version (expect v5.4.0): v5.18.0 (VALID)
iproute2 libbpf version (expect v0.8.0): v0.8.0 (VALID)
```

![](./img/linux_datapath.drawio.svg)

## Example Usage

```yaml
collectors:
- address: 10.146.0.6:2100
templates:
- id: 1024
  template:
  - FlowEndMilliseconds
  - FlowStartMilliseconds
  - OctetDeltaCount
  - PacketDeltaCount
  - IpVersion
  - FlowDirection
  - SourceIPv4Address
  - DestinationIPv4Address
```

```
git clone <this-repo>
cd <this-repo>
sudo ./misc/create_netns.sh
sudo flowctl meter attach --netns ns0 -n eth1
sudo flowctl meter attach --netns ns0 -n eth2
sudo flowctl meter attach --netns ns0 -n eth3
```

### flowctl usage

```shell
docker run --rm --name tmp -it --privileged --net=host -v /usr/include/asm:/usr/include/asm -v /var/run/netns:/var/run/netns ghcr.io/wide-vsix/linux-flow-exporter:branch-master bash
flowctl meter status
```

```shell
## How to check current flow cache
$ sudo flowctl dump
IFINDEX  PROTO  SRC               DST               PKTS  BYTES
98       6      172.17.0.7:49375  172.67.134.3:80   1707  186818
98       6      172.17.0.7:41585  104.21.25.104:80  1710  187560
98       6      172.17.0.7:37869  104.21.25.104:80  9     486

$ sudo flowctl flush -i 98 -p 6 -s 172.17.0.7 -S 37869 -d 104.21.25.104 -D 80 # one cache
$ sudo flowctl flush --all # all caches
```

## Limitation

This software works ONLY for tcp.

## Utilities

```
docker run --rm -td --name tmp1 nicolaka/netshoot bash
```

## Background Why we need

- conntrack doesn't support async traffic
- libpcap based approach consume extreamly big computing cost

REFS
- [Let's read RFC regarding IPFIX (ja) by Asama-san](https://enog.jp/wordpress/wp-content/uploads/2011/12/ipfix.pdf)
- [SKB Definition](https://elixir.bootlin.com/linux/latest/source/include/linux/skbuff.h)
- [Connection Tracking (conntrack): Design and Implementation Inside Linux Kernel](https://arthurchiao.art/blog/conntrack-design-and-implementation/)
- [Packet mark in a Cloud Native world, LPC](https://lpc.events/event/7/contributions/683/attachments/554/979/lpc20-pkt-mark-slides.pdf)
- [VMware NSX IPFIX for Distributed Firewall](https://docs.vmware.com/en/VMware-NSX-Data-Center-for-vSphere/6.4/com.vmware.nsx.admin.doc/GUID-2C625B52-17F0-4604-B5C9-6DF1FA9A70F8.html)
- [VMware NSX IPFIX for Logical Switch](https://docs.vmware.com/en/VMware-NSX-Data-Center-for-vSphere/6.4/com.vmware.nsx.admin.doc/GUID-6054CF07-3019-4539-A6CC-1F613E275E27.html)
- [Comparison and Practice of packet processing implementations and acceleration methods (ja), Ebiken-san, Higebu-san, JANOG45](https://www.janog.gr.jp/meeting/janog45/program/pktfwd/)
- [IN-kernel metadata propagation technique from XDP buffer to SKB](https://github.com/torvalds/linux/blob/master/samples/bpf/xdp2skb_meta_kern.c)
- [Private Discussion for metadata practice in eBPF](https://netmoles.slack.com/archives/C01DYBEETN0/p1667363998874089)
- [One of the Reference design for traffic control mech using eBPF(both xdp and tc), ENOG63 by Higebu-san](https://www.docswell.com/s/higebu/ZQWRMZ-xdp-based-mobile-network-data-plane#p21)
- [An open, unofficial registry of linux packet mark bits (aka fwmark, connmark, netfilter, iptables, nftables)](https://github.com/fwmark/registry)
- [BPF Features by Linux Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)

## Specification

### Supported Text Log Keys

supported
```
src, string
dst, string
proto, string
starttime
endtime
pkts
bytes
```

consideration to support
```
matched acl rule number
```

### Supported IPFIX IETF IE

reference: [IANA registration](https://www.iana.org/assignments/ipfix/ipfix.xhtml)

```
  {"FlowEndMilliseconds", netflow.IPFIX_FIELD_flowEndMilliseconds, 8},
  {"FlowStartMilliseconds", netflow.IPFIX_FIELD_flowStartMilliseconds, 8},
  {"FlowEndNanoseconds", netflow.IPFIX_FIELD_flowEndNanoseconds, 8},
  {"FlowStartNanoseconds", netflow.IPFIX_FIELD_flowStartNanoseconds, 8},
  {"OctetDeltaCount", netflow.IPFIX_FIELD_octetDeltaCount, 8},
  {"PacketDeltaCount", netflow.IPFIX_FIELD_packetDeltaCount, 8},
  {"IpVersion", netflow.IPFIX_FIELD_ipVersion, 1},
  {"IngressInterface", netflow.IPFIX_FIELD_ingressInterface, 4},
  {"EgressInterface", netflow.IPFIX_FIELD_egressInterface, 4},
  {"SourceIPv4Address", netflow.IPFIX_FIELD_sourceIPv4Address, 4},
  {"DestinationIPv4Address", netflow.IPFIX_FIELD_destinationIPv4Address, 4},
  {"ProtocolIdentifier", netflow.IPFIX_FIELD_protocolIdentifier, 1},
  {"SourceTransportPort", netflow.IPFIX_FIELD_sourceTransportPort, 2},
  {"DestinationTransportPort", netflow.IPFIX_FIELD_destinationTransportPort, 2},
```

under the development
```
  {"forwardingStatus", 89, 1}
```

follow will be supported, in mid term
```
  {"flowDirection", netflow.IPFIX_FIELD_flowDirection, 1},
  {"tcpControlBits", netflow.IPFIX_FIELD_tcpControlBits, 1},
  {"icmpTypeCodeIPv4", netflow.IPFIX_FIELD_icmpTypeCodeIPv4, 2},
```

follow will be supported, in long term
```
  {"ipClassOfService", netflow.IPFIX_FIELD_ipClassOfService, 1},
  {"sourceIPv4PrefixLength", netflow.IPFIX_FIELD_sourceIPv4PrefixLength, 1},
  {"destinationIPv4PrefixLength", netflow.IPFIX_FIELD_destinationIPv4PrefixLength, 1},
  {"ipNextHopIPv4Address", netflow.IPFIX_FIELD_ipNextHopIPv4Address, 4},
  {"bgpSourceAsNumber", netflow.IPFIX_FIELD_bgpSourceAsNumber, 4},
  {"bgpDestinationAsNumber", netflow.IPFIX_FIELD_bgpDestinationAsNumber, 4},
  {"bgpNextHopIPv4Address", netflow.IPFIX_FIELD_bgpNextHopIPv4Address, 4},
  {"minimumTTL", netflow.IPFIX_FIELD_minimumTTL, 1},
  {"maximumTTL", netflow.IPFIX_FIELD_maximumTTL, 1},
  {"fragmentIdentification", netflow.IPFIX_FIELD_fragmentIdentification, 4},
  {"vlanId", netflow.IPFIX_FIELD_vlanId, 2},
  {"flowEndReason", netflow.IPFIX_FIELD_flowEndReason, 1},
  {"dot1qVlanId", netflow.IPFIX_FIELD_dot1qVlanId, 2},
  {"dot1qCustomerVlanId", netflow.IPFIX_FIELD_dot1qCustomerVlanId, 2},
```


### Supported IPFIX Enterprise IE

Enterprise No: 28972
([Keio University, iana registry](https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers)).
It may be updated by LINE Corporation

```
```

## Pre Build Packages

![](https://github.com/wide-vsix/linux-flow-exporter/actions/workflows/binary_branch.yaml/badge.svg)<br/>
![](https://github.com/wide-vsix/linux-flow-exporter/actions/workflows/binary_release.yaml/badge.svg)<br/>
![](https://github.com/wide-vsix/linux-flow-exporter/actions/workflows/image_branch.yaml/badge.svg)<br/>
![](https://github.com/wide-vsix/linux-flow-exporter/actions/workflows/image_release.yaml/badge.svg)<br/>

You can use
[automated build container images](https://github.com/wide-vsix/linux-flow-exporter/pkgs/container/linux-flow-exporter/versions?filters%5Bversion_type%5D=tagged) or
[automated build elf-binary](https://github.com/wide-vsix/linux-flow-exporter/releases).
Both are automatically created by updating main-branch and creating release.
Please note that flowctl depends on clang, iproute2 and linux kernel.
You can use `flowctl dependency-check` to check for dependency problems.

for container (latest version)
```
docker run -it --rm --privileged --net=host \
  -v /usr/include/asm:/usr/include/asm \
  -v /var/run/netns:/var/run/netns \
  ghcr.io/wide-vsix/linux-flow-exporter:branch-main bash
flowctl version
```

for container (specified version)
```
docker run -it --rm --privileged --net=host \
  -v /usr/include/asm:/usr/include/asm \
  -v /var/run/netns:/var/run/netns \
  ghcr.io/wide-vsix/linux-flow-exporter:v0.0.5 bash
flowctl version
```

for binary (latest version)
```
curl -Lo /usr/local/bin/flowctl https://github.com/wide-vsix/linux-flow-exporter/releases/download/branch-main/flowctl.linux-amd64
chmod +x /usr/local/bin/flowctl
flowctl version
```

for binary (specified version)
```
curl -Lo /usr/local/bin/flowctl https://github.com/wide-vsix/linux-flow-exporter/releases/download/v0.0.5/flowctl.linux-amd64
chmod +x /usr/local/bin/flowctl
flowctl version
```

## Licence

The user space components are licensed under the
[Apache License, Version 2.0](https://github.com/wide-vsix/linux-flow-exporter/blob/main/LICENSE).
The BPF code templates are dual-licensed under the
[General Public License](https://github.com/wide-vsix/linux-flow-exporter/blob/main/bpf/LICENSE.GPL-2.0),
Version 2.0 (only) and the
[2-Clause BSD License](https://github.com/wide-vsix/linux-flow-exporter/blob/main/bpf/LICENSE.BSD-2-Clause)
(you can use the terms of either license, at your option).
