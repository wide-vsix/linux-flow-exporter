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
cat <<EOF > /var/run/flowctl/hookbatch_all1.sh
#!/bin/sh
jq '[.[] | . + {foo1:"foo1"}]' \\
 | jq '[.[] | . + {foo2:"foo2"}]' \\
 | jq '[.[] | . + {foo3:"foo3"}]' \\
 | jq '[.[] | . + {foo4:"foo4"}]' \\
 | jq '[.[] | . + {foo5:"foo5"}]' \\
 | jq '[.[] | . + {foo6:"foo6"}]' \\
 | jq '[.[] | . + {foo7:"foo7"}]' \\
 | jq '[.[] | . + {foo8:"foo8"}]'
EOF
cat <<EOF > /var/run/flowctl/hookbatch_all2.sh
#!/bin/sh
jq '[.[] | . + {foo1:"foo1",foo2:"foo2",foo3:"foo3",foo4:"foo4",foo5:"foo5",foo6:"foo6",foo7:"foo7",foo8:"foo8"}]'
EOF
chmod +x /var/run/flowctl/hook*.sh
