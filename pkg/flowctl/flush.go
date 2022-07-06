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
	"net"

	"github.com/spf13/cobra"
	"github.com/wide-vsix/linux-flow-exporter/pkg/ebpfmap"
	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

var cliOptFlush = struct {
	All     bool
	Ifindex int
	Proto   int
	Saddr   string
	Daddr   string
	Sport   int
	Dport   int
}{}

func NewCommandFlush() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "flush",
		RunE: fnFlush,
	}
	cmd.Flags().BoolVarP(&cliOptFlush.All, "all", "A", false,
		"Flush all cache entries")
	cmd.Flags().IntVarP(&cliOptFlush.Ifindex, "ifindex", "i", 0,
		"Specifiy flow ifindex")
	cmd.Flags().IntVarP(&cliOptFlush.Proto, "proto", "p", 0,
		"Specifiy flow protocol (6,11,etc..)")
	cmd.Flags().IntVarP(&cliOptFlush.Sport, "sport", "S", 0,
		"Specifiy flow source port")
	cmd.Flags().IntVarP(&cliOptFlush.Dport, "dport", "D", 0,
		"Specifiy flow dest port")
	cmd.Flags().StringVarP(&cliOptFlush.Saddr, "saddr", "s", "",
		"Specifiy flow source address")
	cmd.Flags().StringVarP(&cliOptFlush.Daddr, "daddr", "d", "",
		"Specifiy flow dest address")
	return cmd
}

func fnFlush(cmd *cobra.Command, args []string) error {
	if cliOptFlush.All {
		if err := ebpfmap.DeleteAll(); err != nil {
			return err
		}
	} else {
		if err := ebpfmap.Delete(ebpfmap.FlowKey{
			IngressIfindex: uint32(cliOptFlush.Ifindex),
			Proto:          uint8(cliOptFlush.Proto),
			Saddr:          util.ConvertIPToUint32(net.ParseIP(cliOptFlush.Saddr)),
			Daddr:          util.ConvertIPToUint32(net.ParseIP(cliOptFlush.Daddr)),
			Sport:          uint16(cliOptFlush.Sport),
			Dport:          uint16(cliOptFlush.Dport),
		}); err != nil {
			return err
		}
	}
	return nil
}
