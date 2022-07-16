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

Requirements(I tested with):
- `uname -r`: 5.15.0-1008-gcp
- `ip -V`: ip utility, iproute2-5.18.0, libbpf 0.8.0
  - iproute2 is needed to attach ebpf program into the kernel.

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

### flowctl usage
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
curl -XDELETE http://$ELASTIFLOW_ES_IPADDRESS:9200/elastiflow-flow-codex-1.4-1970.01.01
```
