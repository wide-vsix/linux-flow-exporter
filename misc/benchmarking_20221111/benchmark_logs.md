## Appendix

test command
```
> iperf3 -c 10.2.0.2 -P128 -t5
```

fixed configuration
```
maxIpfixMessageLen: 100
timerFinishedDrainSeconds: 1
timerForceDrainSeconds: 100000
timerTemplateFlushSeconds: 100000
```

fixed commands
```
#!/bin/sh
mkdir -p /var/run/flowctl
echo "#!/bin/sh\njq '. + {foo1: \"foo1\"}'" > /var/run/flowctl/hook1.sh
echo "#!/bin/sh\njq '. + {foo2: \"foo2\"}'" > /var/run/flowctl/hook2.sh
echo "#!/bin/sh\njq '. + {foo3: \"foo3\"}'" > /var/run/flowctl/hook3.sh
echo "#!/bin/sh\njq '. + {foo4: \"foo4\"}'" > /var/run/flowctl/hook4.sh
echo "#!/bin/sh\njq '. + {foo5: \"foo5\"}'" > /var/run/flowctl/hook5.sh
echo "#!/bin/sh\njq '. + {foo6: \"foo6\"}'" > /var/run/flowctl/hook6.sh
echo "#!/bin/sh\njq '. + {foo7: \"foo7\"}'" > /var/run/flowctl/hook7.sh
echo "#!/bin/sh\njq '. + {foo8: \"foo8\"}'" > /var/run/flowctl/hook8.sh
cat <<EOF > /var/run/flowctl/hook_all1.sh
#!/bin/sh
jq '. + {foo1: "foo1"}' \
 | jq '. + {foo2: "foo2"}' \
 | jq '. + {foo3: "foo3"}' \
 | jq '. + {foo4: "foo4"}' \
 | jq '. + {foo5: "foo5"}' \
 | jq '. + {foo6: "foo6"}' \
 | jq '. + {foo7: "foo7"}' \
 | jq '. + {foo8: "foo8"}'
EOF
cat <<EOF > /var/run/flowctl/hook_all2.sh
#!/bin/sh
jq '.+{foo1:"foo1",foo2:"foo2",foo3:"foo3",foo4:"foo4",foo5:"foo5",foo6:"foo6",foo7:"foo7",foo8:"foo8"}'
EOF
chmod +x /var/run/flowctl/hook*.sh
```

```
outputs:
- log:
    file: /tmp/flowlog.json

{"level":"info","msg":"drain finished flows","usec":4618,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":5086,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":7614,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - shell: "#!/bin/sh\njq '. + {foo1: \"foo1\"}'"

{"level":"info","msg":"drain finished flows","usec":8347875,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":8343217,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":8315474,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - shell: "#!/bin/sh\njq '. + {foo1: \"foo1\"}'"
    - shell: "#!/bin/sh\njq '. + {foo2: \"foo2\"}'"

{"level":"info","msg":"drain finished flows","usec":16466085,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":16467925,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":16415695,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - shell: "#!/bin/sh\njq '. + {foo1: \"foo1\"}'"
    - shell: "#!/bin/sh\njq '. + {foo2: \"foo2\"}'"
    - shell: "#!/bin/sh\njq '. + {foo3: \"foo3\"}'"
    - shell: "#!/bin/sh\njq '. + {foo4: \"foo4\"}'"
    - shell: "#!/bin/sh\njq '. + {foo5: \"foo5\"}'"
    - shell: "#!/bin/sh\njq '. + {foo6: \"foo6\"}'"
    - shell: "#!/bin/sh\njq '. + {foo7: \"foo7\"}'"
    - shell: "#!/bin/sh\njq '. + {foo8: \"foo8\"}'"


{"level":"info","msg":"drain finished flows","usec":65414095,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":65104397,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":65380369,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - command: /var/run/flowctl/hook1.sh

{"level":"info","msg":"drain finished flows","usec":8116680,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":8073259,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":8144323,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - command: /var/run/flowctl/hook1.sh
    - command: /var/run/flowctl/hook2.sh
 

{"level":"info","msg":"drain finished flows","usec":16311184,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":16360520,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":16176635,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - command: /var/run/flowctl/hook1.sh
    - command: /var/run/flowctl/hook2.sh
    - command: /var/run/flowctl/hook3.sh
    - command: /var/run/flowctl/hook4.sh
    - command: /var/run/flowctl/hook5.sh
    - command: /var/run/flowctl/hook6.sh
    - command: /var/run/flowctl/hook7.sh
    - command: /var/run/flowctl/hook8.sh

{"level":"info","msg":"drain finished flows","usec":64781848,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":65212016,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":64988219,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - command: /var/run/flowctl/hook_all1.sh

{"level":"info","msg":"drain finished flows","usec":2085080,"nFlows":34} 
{"level":"info","msg":"drain finished flows","usec":2090360,"nFlows":34}

{"level":"info","msg":"drain finished flows","usec":4068813,"nFlows":66}
{"level":"info","msg":"drain finished flows","usec":4074041,"nFlows":66}
{"level":"info","msg":"drain finished flows","usec":4069566,"nFlows":66}

{"level":"info","msg":"drain finished flows","usec":7909099,"nFlows":130}
{"level":"info","msg":"drain finished flows","usec":7975187,"nFlows":130}
{"level":"info","msg":"drain finished flows","usec":8010269,"nFlows":130}

{"level":"info","msg":"drain finished flows","usec":15793583,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":15694148,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":15797545,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - command: /var/run/flowctl/hook_all2.sh

{"level":"info","msg":"force drain current flows","usec":1079169,"nFlows":34}
{"level":"info","msg":"force drain current flows","usec":1077704,"nFlows":34}
{"level":"info","msg":"force drain current flows","usec":1070113,"nFlows":34}

(2106597+2086915)/2
(4105261+4095091+4131419)/3

{"level":"info","msg":"drain finished flows","usec":8125250,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":8160731,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":8215767,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - shell: |
        #!/bin/sh
        jq '[.[] | . + {foo1:"foo1"}]' \
        | jq '[.[] | . + {foo2:"foo2"}]' \
        | jq '[.[] | . + {foo3:"foo3"}]' \
        | jq '[.[] | . + {foo4:"foo4"}]' \
        | jq '[.[] | . + {foo5:"foo5"}]' \
        | jq '[.[] | . + {foo6:"foo6"}]' \
        | jq '[.[] | . + {foo7:"foo7"}]' \
        | jq '[.[] | . + {foo8:"foo8"}]'

258: (129003+131560+130863)/3

{"level":"info","msg":"drain finished flows","usec":129003,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":131560,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":130863,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - command: /var/run/flowctl/hookbatch_all1.sh #many-jq

34: (69832+74551+70318)/3
{"level":"info","msg":"force drain current flows","usec":69832,"nFlows":34}
{"level":"info","msg":"force drain current flows","usec":74551,"nFlows":34}
{"level":"info","msg":"force drain current flows","usec":70318,"nFlows":34}

66: (75263+78929+78031)/3
{"level":"info","msg":"drain finished flows","usec":75263,"nFlows":66}
{"level":"info","msg":"drain finished flows","usec":78929,"nFlows":66}
{"level":"info","msg":"drain finished flows","usec":78031,"nFlows":66}

130: (99978+96594+95671)/3
{"level":"info","msg":"drain finished flows","usec":99978,"nFlows":130}
{"level":"info","msg":"drain finished flows","usec":96594,"nFlows":130}
{"level":"info","msg":"drain finished flows","usec":95671,"nFlows":130}

258: (130711+127055+129459)/3
{"level":"info","msg":"drain finished flows","usec":130711,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":127055,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":129459,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - shell: |
        #!/bin/sh
        jq '[.[] | . + {foo1:"foo1",foo2:"foo2",foo3:"foo3",foo4:"foo4",foo5:"foo5",foo6:"foo6",foo7:"foo7",foo8:"foo8"}]'

258: (57903+52242+51003)/3

{"level":"info","msg":"drain finished flows","usec":57903,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":52242,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":51003,"nFlows":258}
```

```
outputs:
- log:
    file: /tmp/flowlog.json
    hooks:
    - command: /var/run/flowctl/hookbatch_all2.sh #one-jq

34: (36970+38420+34403)/3
{"level":"info","msg":"force drain current flows","usec":36970,"nFlows":34}
{"level":"info","msg":"force drain current flows","usec":38420,"nFlows":34}
{"level":"info","msg":"force drain current flows","usec":34403,"nFlows":34}

66: (40202+39713+39580)/3
{"level":"info","msg":"force drain current flows","usec":40202,"nFlows":66}
{"level":"info","msg":"force drain current flows","usec":39713,"nFlows":66}
{"level":"info","msg":"force drain current flows","usec":39580,"nFlows":66}

130: (44911+45686+47030)/3
{"level":"info","msg":"force drain current flows","usec":44911,"nFlows":130}
{"level":"info","msg":"force drain current flows","usec":45686,"nFlows":130}
{"level":"info","msg":"force drain current flows","usec":47030,"nFlows":130}

258: (52168+56735+51616)/3
{"level":"info","msg":"drain finished flows","usec":52168,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":56735,"nFlows":258}
{"level":"info","msg":"drain finished flows","usec":51616,"nFlows":258}
```
