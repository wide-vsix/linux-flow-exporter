#!/bin/sh
set -xe

ip netns del ns0 || true
ip netns del ns1 || true
ip netns del ns2 || true
ip netns del ns3 || true
