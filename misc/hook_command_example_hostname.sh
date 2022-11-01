#!/bin/sh
# IN:
# {
#   "src": "10.1.0.1",
#   "dst": "10.2.0.1",
#   "pkts": 10,
#   "bytes": 1000
# }
#
# OUT:
# {
#   "src": "10.1.0.1",
#   "dst": "10.2.0.1",
#   "pkts": 10,
#   "bytes": 1000,
#   "hostname": "machine1"
# }
echo `cat` | jq --arg hostname $(hostname) '. + {hostname: $hostname}'
