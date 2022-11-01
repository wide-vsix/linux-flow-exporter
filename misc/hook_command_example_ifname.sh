#!/bin/sh
# IN:
# {
#   "ingressIfindex": 1,
#   "egressIfindex": 2,
#   "pkts": 10,
#   "bytes": 1000
# }
#
# OUT:
# {
#   "ingressIfindex": 1,
#   "egressIfindex": 2,
#   "ingressIfname": 1,
#   "egressIfname": 2,
#   "pkts": 10,
#   "bytes": 1000
# }
IN=$(cat)
I_IDX=$(echo $IN | jq .ingressIfindex -r)
E_IDX=$(echo $IN | jq .egressIfindex -r )
I_NAME=$(ip -n ns0 -j link | jq --argjson idx $I_IDX '.[] | select(.ifindex == $idx) | .ifname' -r)
E_NAME=$(ip -n ns0 -j link | jq --argjson idx $E_IDX '.[] | select(.ifindex == $idx) | .ifname' -r)
echo $IN | jq --arg i_name $I_NAME --arg e_name $E_NAME '. + {ingressIfname: $i_name, egressIfname: $e_name}'
