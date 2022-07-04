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

	"github.com/spf13/cobra"
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
