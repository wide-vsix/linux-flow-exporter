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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <byteswap.h>
#include <arpa/inet.h>
#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF
#ifndef INTERFACE_MAX_FLOW_LIMIT
#define INTERFACE_MAX_FLOW_LIMIT 8
#endif /* INTERFACE_MAX_FLOW_LIMIT */
#define MAX_INTERFACES 512

#define assert_len(interest, end)                 \
  ({                                              \
    if ((unsigned long)(interest + 1) > data_end) \
      return TC_ACT_SHOT;                         \
  })

#define printk(fmt)                     \
  ({                                    \
    char msg[] = fmt;                   \
    bpf_trace_printk(msg, sizeof(msg)); \
  })

struct flowkey {
  uint32_t ingress_ifindex;
  uint32_t egress_ifindex;
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;
  uint8_t proto;
  uint32_t mark;
}  __attribute__ ((packed));

struct flowval {
  uint32_t cnt;
  uint32_t data_bytes;
  uint64_t flow_start_msec;
  uint64_t flow_end_msec;
  uint8_t finished;
}  __attribute__ ((packed));

struct metricsval {
  uint32_t syn_pkts;
  uint32_t total_pkts;
  uint32_t total_bytes;
  uint32_t overflow_pkts;
  uint32_t overflow_bytes;
}  __attribute__ ((packed));

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, INTERFACE_MAX_FLOW_LIMIT);
  __type(key, struct flowkey);
  __type(value, struct flowval);
} flow_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(uint32_t));
  __uint(value_size, sizeof(uint32_t));
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, uint32_t);
  __type(value, struct metricsval);
} metrics SEC(".maps");

static inline void metrics_count_syn(uint32_t ifindex)
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

static inline void metrics_count_final(struct __sk_buff *skb, bool overflow)
{
  uint32_t ingress_ifindex = skb->ingress_ifindex;
  struct metricsval *mv = bpf_map_lookup_elem(&metrics, &ingress_ifindex);
  if (mv) {
    mv->total_pkts = mv->total_pkts + 1;
    mv->total_bytes = mv->total_bytes + skb->len;
    if (overflow) {
      mv->overflow_pkts = mv->overflow_pkts + 1;
      mv->overflow_bytes = mv->overflow_bytes + skb->len;
    }
  } else {
    struct metricsval initval = {0};
    initval.total_pkts = 1;
    initval.total_bytes = skb->len;
    if (overflow) {
      initval.overflow_pkts = 1;
      initval.overflow_bytes = skb->len;
    }
    bpf_map_update_elem(&metrics, &ingress_ifindex, &initval, BPF_ANY);
  }
}

static inline void record(const struct tcphdr *th, const struct iphdr *ih,
                          struct __sk_buff *skb)
{
  uint16_t dport = th->dest;
  uint16_t sport = th->source;
  uint32_t daddr = ih->daddr;
  uint32_t saddr = ih->saddr;
  uint8_t proto = ih->protocol;
  uint8_t finished = 0;
  uint32_t mark = skb->mark;
  struct flowkey key = {0};
  key.ingress_ifindex = skb->ingress_ifindex;
  key.egress_ifindex = skb->ifindex;
  key.daddr = daddr;
  key.saddr = saddr;
  key.dport = htons(dport);
  key.sport = htons(sport);
  key.proto = proto;
  key.mark = mark;
  if (th->fin > 0 || th->rst > 0)
    finished = 1;

  bool overflow = false;
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
      uint32_t msg = skb->ingress_ifindex;
      bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
      overflow = true;
    }
  }

  metrics_count_final(skb, overflow);
}

static inline int
process_ipv4_tcp(struct __sk_buff *skb)
{
  uint64_t data = skb->data;
  uint64_t data_end = skb->data_end;
  uint64_t pkt_len = 0;

  struct iphdr *ih = (struct iphdr *)(data + sizeof(struct ethhdr));
  assert_len(ih, data_end);
  pkt_len = data_end - data;

  uint8_t hdr_len = ih->ihl * 4;
  struct tcphdr *th = (struct tcphdr *)((char *)ih + hdr_len);
  assert_len(th, data_end);

  record(th, ih, skb);
  return TC_ACT_OK;
}

static inline int
process_ipv4_icmp(struct __sk_buff *skb)
{
  // printk("icmp packet");
  return TC_ACT_OK;
}

static inline int
process_ipv4_udp(struct __sk_buff *skb)
{
  // printk("udp packet");
  return TC_ACT_OK;
}

static inline int
process_ipv4(struct __sk_buff *skb)
{
  uint64_t data = skb->data;
  uint64_t data_end = skb->data_end;
  uint64_t pkt_len = 0;

  struct iphdr *ih = (struct iphdr *)(data + sizeof(struct ethhdr));
  assert_len(ih, data_end);
  pkt_len = data_end - data;

  if (ih->ihl < 5)
    return TC_ACT_SHOT;

  switch (ih->protocol) {
  case IPPROTO_ICMP:
    return process_ipv4_icmp(skb);
  case IPPROTO_TCP:
    return process_ipv4_tcp(skb);
  case IPPROTO_UDP:
    return process_ipv4_udp(skb);
  default:
    return TC_ACT_OK;
  }
}

static inline int
process_ethernet(struct __sk_buff *skb)
{
  uint64_t data = skb->data;
  uint64_t data_end = skb->data_end;
  uint64_t pkt_len = 0;

  struct ethhdr *eth_hdr = (struct ethhdr *)data;
  assert_len(eth_hdr, data_end);
  pkt_len = data_end - data;

  switch (htons(eth_hdr->h_proto)) {
  case 0x0800:
    return process_ipv4(skb);
  default:
    return TC_ACT_SHOT;
  }
}

SEC("tc-ingress") int
count_packets_ingress(struct __sk_buff *skb)
{
  return process_ethernet(skb);
}

SEC("tc-egress") int
count_packets_egress(struct __sk_buff *skb)
{
  return process_ethernet(skb);
}

char __license[] SEC("license") = "GPL";
