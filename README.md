# linux-flow-exporter
eBPF based IPFIX/NetFlow exporter.

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

## Limitation

This software works ONLY for tcp.
