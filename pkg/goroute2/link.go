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

type LinkDetailXdpProg struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Tag         string `json:"tag"`
	Jited       int    `json:"jited"`
	LoadTime    uint64 `json:"load_time"`
	CreateByUid int    `json:"created_by_uid"`
	BtfID       int    `json:"btf_id"`
}

type XdpMode int

func (xm XdpMode) String() string {
	switch int(xm) {
	case 2:
		return "generic"
	case 1:
		return "native"
	default:
		return "unknown"
	}
}

type LinkDetailXdp struct {
	Mode XdpMode           `json:"mode"`
	Prog LinkDetailXdpProg `json:"prog"`
}

type LinkDetail struct {
	Ifindex  int            `json:"ifindex"`
	Ifname   string         `json:"ifname"`
	Flags    []string       `json:"flags"`
	Mtu      int            `json:"mtu"`
	Xdp      *LinkDetailXdp `json:"xdp"`
	LinkInfo *struct {
		InfoKind string `json:"info_kind"`
	} `json:"linkinfo"`
}

func GetLinkDetail(netns, dev string) (*LinkDetail, error) {
	n := ""
	if netns != "" {
		n = fmt.Sprintf("ip netns exec %s", netns)
	}
	o, err := util.LocalExecutef("%s ip -j -d link show dev %s", n, dev)
	if err != nil {
		return nil, err
	}
	ld := []LinkDetail{}
	if err := json.Unmarshal([]byte(o), &ld); err != nil {
		return nil, err
	}
	return &ld[0], nil
}
