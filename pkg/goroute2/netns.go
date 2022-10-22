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

func ListNetns() ([]string, error) {
	o, err := util.LocalExecute("ip -j netns")
	if err != nil {
		return nil, err
	}
	type Netns struct {
		Name string `json:"name"`
	}
	netnss := []Netns{}
	if err := json.Unmarshal([]byte(o), &netnss); err != nil {
		return nil, err
	}
	ret := []string{}
	for _, netns := range netnss {
		ret = append(ret, netns.Name)
	}
	return ret, nil
}

type Link struct {
	Ifindex   uint32 `json:"ifindex"`
	Ifname    string `json:"ifname"`
	Operstate string `json:"operstate"`
	Linkmode  string `json:"linkmode"`
	Group     string `json:"group"`
	LinkType  string `json:"link_type"`
	Address   string `json:"address"`
	Broadcast string `json:"broadcast"`
	Mtu       int    `json:"mtu"`
}

func ListLink(netns string) ([]Link, error) {
	n := ""
	if netns != "" {
		n = fmt.Sprintf("ip netns exec %s", netns)
	}
	o, err := util.LocalExecutef("%s ip -d -j link list", n)
	if err != nil {
		return nil, err
	}
	links := []Link{}
	if err := json.Unmarshal([]byte(o), &links); err != nil {
		return nil, err
	}
	return links, nil
}
