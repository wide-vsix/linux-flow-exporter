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

package exporter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

var core = struct {
	templates []IPFixFlowSet
}{}

func getTemplateLength(id int) (int, error) {
	for _, template := range core.templates {
		if int(template.Template.TemplateID) == id {
			len := 0
			for _, field := range template.Template.Fields {
				len += int(field.FieldLength)
			}
			return len, nil
		}
	}
	return 0, fmt.Errorf("not found")
}

func getTemplateFields(id int) ([]IPFixFlowTemplateField, error) {
	for _, template := range core.templates {
		if int(template.Template.TemplateID) == id {
			return template.Template.Fields, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

var cliOpt struct {
	configfile string
}

type IPFixMessage struct {
	Header   IPFixHeader
	FlowSets []IPFixFlowSet
}

type IPFixHeader struct {
	VersionNumber  uint16
	SysupTime      uint32
	SequenceNumber uint32
	SourceID       uint32
}

type IPFixFlowSet struct {
	FlowSetID uint16            `yaml:"flowSetId"`
	Template  IPFixFlowTemplate `yaml:"template,omitempty"`
	Flow      []IPFixFlow       `yaml:"flow"`
}

// https://www.rfc-editor.org/rfc/rfc3954.html#section-5.2
type IPFixFlowTemplate struct {
	TemplateID uint16
	Fields     []IPFixFlowTemplateField
}

// https://www.rfc-editor.org/rfc/rfc3954.html#section-5.2
type IPFixFlowTemplateField struct {
	FieldType   uint16
	FieldLength uint16
}

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "cmd",
		RunE: appMain,
	}
	cmd.Flags().StringVarP(&cliOpt.configfile, "config", "c", "./config.yaml",
		"Specifiy the configuration file")
	return cmd
}

func appMain(cmd *cobra.Command, args []string) error {
	if err := config.Read(cliOpt.configfile); err != nil {
		return err
	}

	msgs, err := generateIPFixTemplate()
	if err != nil {
		return err
	}

	for _, msg := range msgs {
		buf := &bytes.Buffer{}
		if err := msg.ToBuffer(buf); err != nil {
			return err
		}
		for _, collector := range config.Collectors {
			if err := udptransmit(collector.Address, buf); err != nil {
				return err
			}
		}
	}
	return nil
}

func udptransmit(dst string, buf *bytes.Buffer) error {
	conn, err := net.Dial("udp", dst)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

func (m *IPFixMessage) ToBuffer(buf *bytes.Buffer) error {
	cnt := 16 // ipfix message header length (const)
	for _, fs := range m.FlowSets {
		cnt += 4               // ipfix flowset header length (const)
		if fs.FlowSetID == 0 { // template
			cnt += 4
			cnt += 4 * len(fs.Template.Fields)
		} else { // flow
			l, err := getTemplateLength(int(fs.FlowSetID))
			if err != nil {
				return err
			}
			cnt += l + 4
		}
	}

	// https://www.rfc-editor.org/rfc/rfc3954.html#section-5.1
	if err := binary.Write(buf, binary.BigEndian, &struct {
		VersionNumber  uint16
		Count          uint16
		SysupTime      uint32
		SequenceNumber uint32
		SourceID       uint32
	}{
		VersionNumber:  m.Header.VersionNumber,
		Count:          uint16(cnt),
		SysupTime:      m.Header.SysupTime,
		SequenceNumber: m.Header.SequenceNumber,
		SourceID:       m.Header.SourceID,
	}); err != nil {
		return err
	}

	// https://www.rfc-editor.org/rfc/rfc3954.html#section-5.2
	for _, flowset := range m.FlowSets {
		if err := flowset.ToBuffer(buf); err != nil {
			return err
		}
	}
	return nil
}

// https://www.rfc-editor.org/rfc/rfc3954.html#section-5.2
func (fs *IPFixFlowSet) ToBuffer(buf *bytes.Buffer) error {
	if fs.FlowSetID == 0 {
		const flowsetHdrLen = 8
		flowsetlen := len(fs.Template.Fields)*4 + flowsetHdrLen

		if err := binary.Write(buf, binary.BigEndian, &struct {
			FlowSetID  uint16
			Length     uint16
			TemplateID uint16
			FieldCount uint16
		}{
			2, // TODO(slankdev): 2 is FLOW-TEMPLATE
			uint16(flowsetlen),
			fs.Template.TemplateID,
			uint16(len(fs.Template.Fields)),
		}); err != nil {
			return err
		}
		for _, field := range fs.Template.Fields {
			if err := binary.Write(buf, binary.BigEndian, &field); err != nil {
				return err
			}
		}
	} else {
		const flowsetHdrLen = 4
		templateLen, err := getTemplateLength(int(fs.FlowSetID))
		if err != nil {
			return err
		}
		flowsetlen := len(fs.Flow)*templateLen + flowsetHdrLen
		if err := binary.Write(buf, binary.BigEndian, &struct {
			FlowSetID uint16
			Length    uint16
		}{
			fs.FlowSetID,
			uint16(flowsetlen),
		}); err != nil {
			return err
		}

		for _, flow := range fs.Flow {
			if err := flow.ToBuffer(buf, fs.FlowSetID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (flow *IPFixFlow) ToBuffer(buf *bytes.Buffer, templateID uint16) error {
	fields, err := getTemplateFields(int(templateID))
	if err != nil {
		return err
	}

	for _, field := range fields {
		if err := binaryWrite(field.FieldType, buf, flow); err != nil {
			return err
		}
	}
	return nil
}
