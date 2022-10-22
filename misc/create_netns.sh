#!/bin/sh
#        10.2.0.0/24
#        .2       .1
# [ns2](eth0)---(eth3)   .1        .2
#                 [ns0](eth1)----(eth0)[ns1]
# [ns3](eth0)---(eth4)       10.1.0.0/24
#        .2       .1
#        10.3.0.0/24
set -xe

ip netns add ns0
ip netns add ns1
ip netns add ns2
ip netns add ns3

ip -n ns0 link set lo up
ip -n ns1 link set lo up
ip -n ns2 link set lo up
ip -n ns3 link set lo up

ip link add eth0 netns ns1 type veth peer name eth1 netns ns0
ip link add eth0 netns ns2 type veth peer name eth2 netns ns0
ip link add eth0 netns ns3 type veth peer name eth3 netns ns0

ip -n ns0 link set eth1 up
ip -n ns0 link set eth2 up
ip -n ns0 link set eth3 up
ip -n ns1 link set eth0 up
ip -n ns2 link set eth0 up
ip -n ns3 link set eth0 up

ip -n ns0 addr add 10.1.0.1/24 dev eth1
ip -n ns0 addr add 10.2.0.1/24 dev eth2
ip -n ns0 addr add 10.3.0.1/24 dev eth3
ip -n ns1 addr add 10.1.0.2/24 dev eth0
ip -n ns2 addr add 10.2.0.2/24 dev eth0
ip -n ns3 addr add 10.3.0.2/24 dev eth0

ip -n ns1 route add default via 10.1.0.1
ip -n ns2 route add default via 10.2.0.1
ip -n ns3 route add default via 10.3.0.1
