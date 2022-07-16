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

package flowctl

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/wide-vsix/linux-flow-exporter/pkg/ebpfmap"
	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

var cliOptDump = struct {
	Output string
}{}

func NewCommandDump() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "dump",
		RunE: fnDump,
	}
	cmd.Flags().StringVarP(&cliOptDump.Output, "output", "o", "normal",
		"Output format. One of: normal|wide|json")
	return cmd
}

func fnDump(cmd *cobra.Command, args []string) error {
	flows, err := ebpfmap.Dump()
	if err != nil {
		return err
	}

	table := util.NewTableWriter(os.Stdout)
	hdr := []string{"Ifindex", "Proto", "Src", "Dst", "Pkts", "Bytes"}
	if cliOptDump.Output == "wide" {
		hdr = append(hdr, []string{"Start", "End", "Finished"}...)
	}
	table.SetHeader(hdr)

	for _, flow := range flows {
		data := []string{
			fmt.Sprintf("%d", flow.Key.Ifindex),
			fmt.Sprintf("%d", flow.Key.Proto),
			fmt.Sprintf("%s:%d", util.ConvertUint32ToIP(flow.Key.Saddr), flow.Key.Sport),
			fmt.Sprintf("%s:%d", util.ConvertUint32ToIP(flow.Key.Daddr), flow.Key.Dport),
			fmt.Sprintf("%d", flow.Val.FlowPkts),
			fmt.Sprintf("%d", flow.Val.FlowBytes),
		}
		if cliOptDump.Output == "wide" {
			data = append(data, []string{
				fmt.Sprintf("%d", flow.Val.FlowStartMilliSecond),
				fmt.Sprintf("%d", flow.Val.FlowEndMilliSecond),
				strconv.FormatBool(flow.Val.Finished == uint8(1)),
			}...)
		}
		table.Append(data)
	}
	table.Render()
	return nil
}
