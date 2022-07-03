#!/usr/bin/env python3
import json
import pprint
import socket
import ipaddress
import subprocess
import sys


def execute(cmd, nojson=False):
  res = subprocess.check_output(cmd.split())
  if nojson:
    return
  return json.loads(res)


flow_stats_exist = False
for em in execute("sudo bpftool map -j"):
    if em["name"] == "flow_stats":
        flow_stats_exist = True
        break
if not flow_stats_exist:
    print("nothing")
    sys.exit(0)

stats = {}
for data in execute("sudo bpftool map dump name flow_stats"):
    def countup(element):
        daddr = element['key']['daddr']
        saddr = element['key']['saddr']
        daddr = str(ipaddress.IPv4Address(socket.htonl(daddr)))
        saddr = str(ipaddress.IPv4Address(socket.htonl(saddr)))
        key = "{}/{}/{}:{}->{}:{}".format(
            element['key']['ifindex'],
            element['key']['proto'],
            saddr, element['key']['sport'],
            daddr, element['key']['dport'])
        val = stats.get(key, {})
        cnt = val.get("cnt", 0)
        data_bytes = val.get("data_bytes", 0)
        for value in element['values']:
            cnt += value['value']['cnt']
            data_bytes += value['value']['data_bytes']
        val["cnt"] = cnt
        val["data_bytes"] = data_bytes
        stats[key] = val

    if "elements" in data:
        for element in data['elements']:
            countup(element)
    else:
        countup(data)
pprint.pprint(stats)
