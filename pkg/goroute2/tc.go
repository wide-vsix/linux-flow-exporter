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

package goroute2

import (
	"encoding/json"
	"fmt"

	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

type TcFilterRule struct {
	Protocol string `json:"protocol"`
	Pref     uint   `json:"pref"`
	Kind     string `json:"kind"`
	Chain    uint   `json:"chain"`
	Options  struct {
		Handle  string `json:"handle"`
		BpfName string `json:"bpf_name"`
		NotInHw bool   `json:"not_in_hw"`
		Prog    struct {
			ID    int    `json:"id"`
			Name  string `json:"name"`
			Tag   string `json:"tag"`
			Jited int    `json:"jited"`
		} `json:"prog"`
	} `json:"options"`
}

func ListTcFilterRules(netns, dev string) ([]TcFilterRule, error) {
	n := ""
	if netns != "" {
		n = fmt.Sprintf("ip netns exec %s", netns)
	}
	o, err := util.LocalExecutef("%s tc -j filter list dev %s egress", n, dev)
	if err != nil {
		return nil, err
	}
	rules := []TcFilterRule{}
	if err := json.Unmarshal([]byte(o), &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// $ tc -j qdisc list dev eth1 | jq
// [
//   {
//     "kind": "noqueue",
//     "handle": "0:",
//     "root": true,
//     "refcnt": 2,
//     "options": {}
//   },
//   {
//     "kind": "clsact",
//     "handle": "ffff:",
//     "parent": "ffff:fff1",
//     "options": {}
//   }
// ]
type TcQdisc struct {
	Kind   string `json:"kind"`
	Handle string `json:"handle"`
	Root   bool   `json:"root"`
	Refcnt uint   `json:"refcnt"`
}

func ListTcQdisc(netns, dev string) ([]TcQdisc, error) {
	n := ""
	if netns != "" {
		n = fmt.Sprintf("ip netns exec %s", netns)
	}
	o, err := util.LocalExecutef("%s tc -j qdisc list dev %s", n, dev)
	if err != nil {
		return nil, err
	}
	rules := []TcQdisc{}
	if err := json.Unmarshal([]byte(o), &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func ClsActIsEnabled(netns, dev string) (bool, error) {
	qdiscs, err := ListTcQdisc(netns, dev)
	if err != nil {
		return false, err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Kind == "clsact" {
			return true, nil
		}
	}
	return false, nil
}
