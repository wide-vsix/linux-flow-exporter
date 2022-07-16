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
	"bytes"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/wide-vsix/linux-flow-exporter/pkg/ebpfmap"
	"github.com/wide-vsix/linux-flow-exporter/pkg/ipfix"
	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

var cliOptIpfix = struct {
	Config   string
	FlowFile string
}{}

func NewCommandIpfix() *cobra.Command {
	cmd := &cobra.Command{
		Use: "ipfix",
	}
	cmd.AddCommand(NewCommandIpfixTemplate())
	cmd.AddCommand(NewCommandIpfixDump())
	cmd.AddCommand(NewCommandIpfixAgent())
	return cmd
}

func NewCommandIpfixTemplate() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "file",
		RunE: fnIpfixTemplate,
	}
	cmd.Flags().StringVarP(&cliOptIpfix.Config, "config", "c", "./config.yaml",
		"Specifiy ipfix configuration")
	cmd.Flags().StringVarP(&cliOptIpfix.FlowFile, "flow", "f", "./flow.yaml",
		"Specifiy ipfix flow file")
	return cmd
}

func fnIpfixTemplate(cmd *cobra.Command, args []string) error {
	config := ipfix.Config{}
	if err := util.FileUnmarshalAsYaml(cliOptIpfix.Config, &config); err != nil {
		return err
	}
	flow := ipfix.FlowFile{}
	if err := util.FileUnmarshalAsYaml(cliOptIpfix.FlowFile, &flow); err != nil {
		return err
	}

	// Transmit Flow Template Message
	buf1 := bytes.Buffer{}
	templateMessage, err := config.ToFlowTemplatesMessage()
	if err != nil {
		return err
	}
	templateMessage.Header.SysupTime = 0      // TODO
	templateMessage.Header.SequenceNumber = 0 // TODO
	templateMessage.Header.SourceID = 0       // TODO
	if err := templateMessage.Write(&buf1); err != nil {
		return err
	}
	for _, c := range config.Collectors {
		if err := util.UdpTransmit(c.LocalAddress, c.RemoteAddress, &buf1); err != nil {
			return err
		}
	}

	// Transmit Flow Data Message
	flowDataMessages, err := flow.ToFlowDataMessages(&config, 0)
	if err != nil {
		return err
	}
	for _, flowDataMessage := range flowDataMessages {
		buf2 := bytes.Buffer{}
		if err := flowDataMessage.Write(&buf2, &config); err != nil {
			return err
		}
		for _, c := range config.Collectors {
			if err := util.UdpTransmit(c.LocalAddress, c.RemoteAddress, &buf2); err != nil {
				return err
			}
		}
	}

	return nil
}

func NewCommandIpfixDump() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "dump",
		RunE: fnIpfixDump,
	}
	cmd.Flags().StringVarP(&cliOptIpfix.Config, "config", "c", "./config.yaml",
		"Specifiy ipfix configuration")
	return cmd
}

func fnIpfixDump(cmd *cobra.Command, args []string) error {
	config := ipfix.Config{}
	if err := util.FileUnmarshalAsYaml(cliOptIpfix.Config, &config); err != nil {
		return err
	}

	// template
	buf1 := bytes.Buffer{}
	templateMessage, err := config.ToFlowTemplatesMessage()
	if err != nil {
		return err
	}
	templateMessage.Header.SysupTime = 0 // TODO
	templateMessage.Header.SysupTime = uint32(util.TimeNow())
	templateMessage.Header.SequenceNumber = 0 // TODO
	templateMessage.Header.SourceID = 0       // TODO
	if err := templateMessage.Write(&buf1); err != nil {
		return err
	}
	for _, c := range config.Collectors {
		if err := util.UdpTransmit(c.LocalAddress, c.RemoteAddress, &buf1); err != nil {
			return err
		}
	}

	// flowdata
	ebpfFlows, err := ebpfmap.Dump()
	if err != nil {
		return err
	}
	//flow, err := T(ebpfFlows)
	flow, err := ebpfmap.ToIpfixFlowFile(ebpfFlows)
	if err != nil {
		return err
	}

	flowDataMessages, err := flow.ToFlowDataMessages(&config, 0)
	if err != nil {
		return err
	}
	// pp.Println(flowDataMessages)
	for _, flowDataMessage := range flowDataMessages {
		flowDataMessage.Header.SysupTime = uint32(util.TimeNow())
		buf2 := bytes.Buffer{}
		if err := flowDataMessage.Write(&buf2, &config); err != nil {
			return err
		}
		for _, c := range config.Collectors {
			if err := util.UdpTransmit(c.LocalAddress, c.RemoteAddress, &buf2); err != nil {
				return err
			}
		}
	}

	return nil
}

func NewCommandIpfixAgent() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "agent",
		RunE: fnIpfixAgent,
	}
	cmd.Flags().StringVarP(&cliOptIpfix.Config, "config", "c", "./config.yaml",
		"Specifiy ipfix configuration")
	return cmd
}

func fnIpfixAgent(cmd *cobra.Command, args []string) error {
	config := ipfix.Config{}
	if err := util.FileUnmarshalAsYaml(cliOptIpfix.Config, &config); err != nil {
		return err
	}

	// template
	buf1 := bytes.Buffer{}
	templateMessage, err := config.ToFlowTemplatesMessage()
	if err != nil {
		return err
	}
	templateMessage.Header.SysupTime = 0 // TODO
	templateMessage.Header.SysupTime = uint32(util.TimeNow())
	templateMessage.Header.SequenceNumber = 0 // TODO
	templateMessage.Header.SourceID = 0       // TODO
	if err := templateMessage.Write(&buf1); err != nil {
		return err
	}
	for _, c := range config.Collectors {
		if err := util.UdpTransmit(c.LocalAddress, c.RemoteAddress, &buf1); err != nil {
			return err
		}
	}

	tickerFinished := time.NewTicker(10 * time.Second)
	ticketForce := time.NewTicker(60 * time.Second)
	tickerForTemplateFlush := time.NewTicker(30 * time.Second)
	perfEvent, err := ebpfmap.StartReader()
	if err != nil {
		return err
	}
	defer close(perfEvent)

	for {
		select {
		case pe := <-perfEvent:
			fmt.Printf("main: map=%d ifindex=%d map-full\n", pe.MapID, pe.Ifindex())
			ebpfFlows, err := ebpfmap.Dump()
			if err != nil {
				return err
			}
			if len(ebpfFlows) == 0 {
				continue
			}
			if err := flushCaches(config); err != nil {
				return err
			}
			if err := ebpfmap.DeleteAll(); err != nil {
				return err
			}

		case <-tickerFinished.C:
			ebpfFlows, err := ebpfmap.Dump()
			if err != nil {
				return err
			}
			if len(ebpfFlows) == 0 {
				continue
			}
			if err := flushCachesFinished(config); err != nil {
				return err
			}
			if err := ebpfmap.DeleteFinished(); err != nil {
				return err
			}

		case <-ticketForce.C:
			ebpfFlows, err := ebpfmap.Dump()
			if err != nil {
				return err
			}
			if len(ebpfFlows) == 0 {
				continue
			}
			if err := flushCaches(config); err != nil {
				return err
			}
			if err := ebpfmap.DeleteAll(); err != nil {
				return err
			}
		case <-tickerForTemplateFlush.C:
			buf1 := bytes.Buffer{}
			templateMessage, err := config.ToFlowTemplatesMessage()
			if err != nil {
				return err
			}
			templateMessage.Header.SysupTime = 0 // TODO
			templateMessage.Header.SysupTime = uint32(util.TimeNow())
			templateMessage.Header.SequenceNumber = 0 // TODO
			templateMessage.Header.SourceID = 0       // TODO
			if err := templateMessage.Write(&buf1); err != nil {
				return err
			}
			for _, c := range config.Collectors {
				if err := util.UdpTransmit(c.LocalAddress, c.RemoteAddress, &buf1); err != nil {
					return err
				}
			}
		}
	}
}

func flushCachesFinished(config ipfix.Config) error {
	ebpfFlows0, err := ebpfmap.Dump()
	if err != nil {
		return err
	}
	ebpfFlows := []ebpfmap.Flow{}
	for _, ebpfFlow := range ebpfFlows0 {
		if ebpfFlow.Val.Finished > 0 {
			ebpfFlows = append(ebpfFlows, ebpfFlow)
		}
	}

	flow, err := ebpfmap.ToIpfixFlowFile(ebpfFlows)
	if err != nil {
		return err
	}

	flowDataMessages, err := flow.ToFlowDataMessages(&config, 0)
	if err != nil {
		return err
	}
	for _, flowDataMessage := range flowDataMessages {
		flowDataMessage.Header.SysupTime = uint32(util.TimeNow())
		buf2 := bytes.Buffer{}
		if err := flowDataMessage.Write(&buf2, &config); err != nil {
			return err
		}
		for _, c := range config.Collectors {
			if err := util.UdpTransmit(c.LocalAddress, c.RemoteAddress, &buf2); err != nil {
				return err
			}
		}
	}
	return nil
}

func flushCaches(config ipfix.Config) error {
	ebpfFlows, err := ebpfmap.Dump()
	if err != nil {
		return err
	}
	flow, err := ebpfmap.ToIpfixFlowFile(ebpfFlows)
	if err != nil {
		return err
	}

	flowDataMessages, err := flow.ToFlowDataMessages(&config, 0)
	if err != nil {
		return err
	}
	for _, flowDataMessage := range flowDataMessages {
		flowDataMessage.Header.SysupTime = uint32(util.TimeNow())
		buf2 := bytes.Buffer{}
		if err := flowDataMessage.Write(&buf2, &config); err != nil {
			return err
		}
		for _, c := range config.Collectors {
			if err := util.UdpTransmit(c.LocalAddress, c.RemoteAddress, &buf2); err != nil {
				return err
			}
		}
	}
	return nil
}
