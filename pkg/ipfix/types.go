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

package ipfix

import (
	"bytes"
	"encoding/binary"
)

type Header struct {
	VersionNumber  uint16
	SysupTime      uint32
	SequenceNumber uint32
	SourceID       uint32
}

type FlowDataMessage struct {
	Header   Header
	FlowSets []FlowSet
}

type FlowSet struct {
	FlowSetID uint16 `yaml:"flowSetId"`
	Flow      []Flow `yaml:"flow"`
}

type TemplateMessage struct {
	Header    Header
	Templates []FlowTemplate
}

type FlowTemplate struct {
	TemplateID uint16
	Fields     []FlowTemplateField
}

type FlowTemplateField struct {
	FieldType   uint16
	FieldLength uint16
}

func (m TemplateMessage) Write(buf *bytes.Buffer) error {
	cnt := 16 // ipfix message header length (const)
	for _, t := range m.Templates {
		cnt += 8                 // ipfix flowset header length (const)
		cnt += 4 * len(t.Fields) // ipfix field definition length
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
	for _, t := range m.Templates {
		const flowsetHdrLen = 8
		flowsetlen := len(t.Fields)*4 + flowsetHdrLen

		if err := binary.Write(buf, binary.BigEndian, &struct {
			FlowSetID  uint16
			Length     uint16
			TemplateID uint16
			FieldCount uint16
		}{
			2, // TODO(slankdev): 2 is FLOW-TEMPLATE
			uint16(flowsetlen),
			t.TemplateID,
			uint16(len(t.Fields)),
		}); err != nil {
			return err
		}
		for _, field := range t.Fields {
			if err := binary.Write(buf, binary.BigEndian, &field); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m FlowDataMessage) Write(buf *bytes.Buffer, config *Config) error {
	cnt := 16 // ipfix message header length (const)
	for _, fs := range m.FlowSets {
		cnt += 4 // ipfix flowset header length (const)
		l, err := config.getTemplateLength(fs.FlowSetID)
		if err != nil {
			return err
		}
		cnt += l * len(fs.Flow)
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

	for _, fs := range m.FlowSets {
		flowSetLen, err := config.getTemplateLength(fs.FlowSetID)
		if err != nil {
			return err
		}

		if err := binary.Write(buf, binary.BigEndian, &struct {
			FlowSetID     uint16
			FlowSetLength uint16
		}{
			FlowSetID:     fs.FlowSetID,
			FlowSetLength: uint16(len(fs.Flow)*flowSetLen + 4),
		}); err != nil {
			return err
		}

		for _, f := range fs.Flow {
			ftypes, err := getTemplateFieldTypes(fs.FlowSetID, config)
			if err != nil {
				return err
			}
			for _, ftype := range ftypes {
				if err := binaryWrite(ftype, buf, &f); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
