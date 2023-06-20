/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 Keio University.
Copyright 2022 Wide Project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF
#ifndef INTERFACE_MAX_FLOW_LIMIT
#define INTERFACE_MAX_FLOW_LIMIT 8
#endif /* INTERFACE_MAX_FLOW_LIMIT */
#define MAX_INTERFACES 512

#define assert_len(interest, end)            \
  ({                                         \
    if ((unsigned long)(interest + 1) > end) \
      return TC_ACT_SHOT;                    \
  })

struct flowkey {
  __u32 ingress_ifindex;
  __u32 egress_ifindex;
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u8 proto;
  __u32 mark;
}  __attribute__ ((packed));

struct flowval {
  __u32 cnt; // pkts;
  __u32 data_bytes; // bytes;
  __u64 flow_start_msec;
  __u64 flow_end_msec;
  __u8 finished;
}  __attribute__ ((packed));

struct metricskey {
  __u32 ingress_ifindex;
  __u32 egress_ifindex;
}  __attribute__ ((packed));

struct metricsval {
  __u32 syn_pkts;
  __u32 total_pkts;
  __u32 total_bytes;
  __u32 overflow_pkts;
  __u32 overflow_bytes;
  __u32 latency_nano_sum;
}  __attribute__ ((packed));

struct meta_info {
  __u64 tstamp;
}  __attribute__ ((packed));

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, INTERFACE_MAX_FLOW_LIMIT);
  __type(key, struct flowkey);
  __type(value, struct flowval);
} flow_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, struct metricskey);
  __type(value, struct metricsval);
} metrics SEC(".maps");

#ifdef DEBUG
static inline void
debug_skb(struct __sk_buff *skb, const char *name)
{
  bpf_printk("%s(%u:%u)", name, skb->ingress_ifindex, skb->ifindex);
  bpf_printk(" tstamp:%u mark:%u l4_hash:%u", skb->tstamp, skb->mark, skb->hash);
  bpf_printk(" cb[0]: %u", skb->cb[0]);
  bpf_printk(" cb[1]: %u", skb->cb[1]);
  bpf_printk(" cb[2]: %u", skb->cb[2]);
  bpf_printk(" cb[3]: %u", skb->cb[3]);
  bpf_printk(" cb[4]: %u", skb->cb[4]);
  bpf_printk(" data_meta: %u", skb->data_meta);
  bpf_printk(" data:      %u", skb->data);
  bpf_printk(" data_end:  %u", skb->data_end);
}
#endif /* DEBUG */

#if 0
static inline void metrics_count_syn(__u32 ifindex)
{
    struct metricsval *mv = bpf_map_lookup_elem(&metrics, &ifindex);
    if (mv) {
      mv->syn_pkts = mv->syn_pkts + 1;
    } else {
      struct metricsval initval = {0};
      initval.syn_pkts = 1;
      bpf_map_update_elem(&metrics, &ifindex, &initval, BPF_ANY);
    }
}
#endif

static inline __u64 forwarding_duration_ns(struct __sk_buff *skb)
{
  if (skb->data_meta < skb->data) {
    struct meta_info *meta = (struct meta_info *)skb->data_meta;
    assert_len(meta, skb->data);
    return bpf_ktime_get_ns() - meta->tstamp;
  } else {
    return 0;
  }
}

static inline void metrics_count_final(struct __sk_buff *skb, __u8 overflow)
{
  struct metricskey key = {};
  key.ingress_ifindex = skb->ingress_ifindex;
  key.egress_ifindex = skb->ifindex;
  struct metricsval *mv = bpf_map_lookup_elem(&metrics, &key);
  if (mv) {
    mv->total_pkts = mv->total_pkts + 1;
    mv->total_bytes = mv->total_bytes + skb->len;
    if (overflow) {
      mv->overflow_pkts = mv->overflow_pkts + 1;
      mv->overflow_bytes = mv->overflow_bytes + skb->len;
    }
    mv->latency_nano_sum += forwarding_duration_ns(skb);
  } else {
    struct metricsval initval = {0};
    initval.total_pkts = 1;
    initval.total_bytes = skb->len;
    if (overflow) {
      initval.overflow_pkts = 1;
      initval.overflow_bytes = skb->len;
    }
    initval.latency_nano_sum = forwarding_duration_ns(skb);
    bpf_map_update_elem(&metrics, &key, &initval, BPF_ANY);
  }
}

static inline void record(const struct tcphdr *th, const struct iphdr *ih,
                          struct __sk_buff *skb)
{
  __u16 dport = th->dest;
  __u16 sport = th->source;
  __u32 daddr = ih->daddr;
  __u32 saddr = ih->saddr;
  __u8 proto = ih->protocol;
  __u8 finished = 0;
  __u32 mark = skb->mark;
  struct flowkey key = {0};
  key.ingress_ifindex = skb->ingress_ifindex;
  key.egress_ifindex = skb->ifindex;
  key.daddr = daddr;
  key.saddr = saddr;
  key.dport = bpf_htons(dport);
  key.sport = bpf_htons(sport);
  key.proto = proto;
  key.mark = mark;
  if (th->fin > 0 || th->rst > 0)
    finished = 1;

  __u8 overflow = 0;
  struct flowval *val = bpf_map_lookup_elem(&flow_stats, &key);
  if (val) {
    val->cnt = val->cnt + 1;
    val->data_bytes = val->data_bytes + skb->len;
    val->flow_end_msec = bpf_ktime_get_ns();
    if (val->finished == 0)
      val->finished = finished;
  } else {
    struct flowval initval = {0};
    initval.cnt = 1;
    initval.data_bytes = skb->len;
    initval.flow_start_msec = bpf_ktime_get_ns();
    initval.finished = finished;
    int ret = bpf_map_update_elem(&flow_stats, &key, &initval, BPF_ANY);
    if (ret != 0) {
      __u32 msg = skb->ingress_ifindex;
      bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
      overflow = 1;
    }
  }

  metrics_count_final(skb, overflow);
}

static inline int
process_ipv4_tcp(struct __sk_buff *skb, __u8 encap_with)
{
  __u64 data = skb->data;
  __u64 data_end = skb->data_end;

  if (encap_with == IPPROTO_IPIP)
    data += sizeof(struct iphdr);

  struct iphdr *ih = (struct iphdr *)(data + sizeof(struct ethhdr));
  assert_len(ih, data_end);

  __u8 hdr_len = ih->ihl * 4;
  struct tcphdr *th = (struct tcphdr *)((char *)ih + hdr_len);
  assert_len(th, data_end);

  record(th, ih, skb);
  return TC_ACT_OK;
}

static inline int
process_ipv4_icmp(struct __sk_buff *skb, __u8 encap_with)
{
  // bpf_printk("icmp packet");
  return TC_ACT_OK;
}

static inline int
process_ipv4_udp(struct __sk_buff *skb, __u8 encap_with)
{
  // bpf_printk("udp packet");
  return TC_ACT_OK;
}

static inline int
process_ipv4_ipip(struct __sk_buff *skb)
{
  __u64 data = skb->data;
  __u64 data_end = skb->data_end;
  __u64 pkt_len = 0;

  struct iphdr *outer_ih = (struct iphdr *)(data + sizeof(struct ethhdr));
  assert_len(outer_ih, data_end);

  struct iphdr *inner_ih = (struct iphdr *)((char *)outer_ih + sizeof(struct iphdr));
  assert_len(inner_ih, data_end);

  switch (inner_ih->protocol) {
  case IPPROTO_ICMP:
    return process_ipv4_icmp(skb, IPPROTO_IPIP);
  case IPPROTO_TCP:
    return process_ipv4_tcp(skb, IPPROTO_IPIP);
  case IPPROTO_UDP:
    return process_ipv4_udp(skb, IPPROTO_IPIP);
  default:
    return TC_ACT_OK;
  }
}

static inline int
process_ipv4(struct __sk_buff *skb)
{
  __u64 data = skb->data;
  __u64 data_end = skb->data_end;
  __u64 pkt_len = 0;

  struct iphdr *ih = (struct iphdr *)(data + sizeof(struct ethhdr));
  assert_len(ih, data_end);
  pkt_len = data_end - data;

  if (ih->ihl < 5)
    return TC_ACT_SHOT;

  switch (ih->protocol) {
  case IPPROTO_ICMP:
    return process_ipv4_icmp(skb, 0);
  case IPPROTO_TCP:
    return process_ipv4_tcp(skb, 0);
  case IPPROTO_UDP:
    return process_ipv4_udp(skb, 0);
  /* encapsulated packets */
  case IPPROTO_IPIP:
    return process_ipv4_ipip(skb);
  default:
    return TC_ACT_OK;
  }
}

static inline int
process_ethernet(struct __sk_buff *skb)
{
  __u64 data = skb->data;
  __u64 data_end = skb->data_end;
  __u64 pkt_len = 0;

  struct ethhdr *eth_hdr = (struct ethhdr *)data;
  assert_len(eth_hdr, data_end);
  pkt_len = data_end - data;

  switch (bpf_htons(eth_hdr->h_proto)) {
  case 0x0800:
    return process_ipv4(skb);
  default:
    return TC_ACT_SHOT;
  }
}

SEC("xdp-ingress") int
xdp_ingress(struct xdp_md *ctx)
{
  int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_info));
  if (ret < 0)
    return XDP_ABORTED;
  return XDP_PASS;
}

SEC("tc-ingress") int
tc_ingress(struct __sk_buff *skb)
{
  struct meta_info *meta = (struct meta_info *)skb->data_meta;
  assert_len(meta, skb->data);
  meta->tstamp = bpf_ktime_get_ns();
  return TC_ACT_OK;
}

SEC("tc-egress") int
tc_egress(struct __sk_buff *skb)
{
  return process_ethernet(skb);
}

char __license[] SEC("license") = "GPL";
