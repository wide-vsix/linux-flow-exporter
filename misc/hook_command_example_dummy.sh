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
#   "foo": "bar"
# }
echo `cat` | jq '. + {foo: "bar"}'
