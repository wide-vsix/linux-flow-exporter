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
	"fmt"
)

type fieldTableItem struct {
	Name   string
	Value  int
	Length int
}

func getIPFixFieldsValueByName(name string) (int, error) {
	for _, field := range ipfixfields {
		if field.Name == name {
			return field.Value, nil
		}
	}
	return 0, fmt.Errorf("not found")
}

func getIPFixFieldsLengthByName(name string) (int, error) {
	for _, field := range ipfixfields {
		if field.Name == name {
			return field.Length, nil
		}
	}
	return 0, fmt.Errorf("not found")
}

func generateIPFixTemplate() ([]IPFixMessage, error) {
	flowsets := []IPFixFlowSet{}
	for _, item := range config.Templates {
		fields := []IPFixFlowTemplateField{}
		for _, template := range item.Template {
			value, err := getIPFixFieldsValueByName(template)
			if err != nil {
				return nil, err
			}
			length, err := getIPFixFieldsLengthByName(template)
			if err != nil {
				return nil, err
			}

			fields = append(fields, IPFixFlowTemplateField{
				FieldType:   uint16(value),
				FieldLength: uint16(length),
			})
		}

		flowsets = append(flowsets, IPFixFlowSet{
			FlowSetID: 0,
			Template: IPFixFlowTemplate{
				TemplateID: item.ID,
				Fields:     fields,
			},
		})
	}
	core.templates = flowsets

	flowsets = append(flowsets, dummyFlowSetData())
	msg := IPFixMessage{
		Header: IPFixHeader{
			VersionNumber:  9,
			SysupTime:      0x00002250,
			UnixSecs:       0x62b7f72d,
			SequenceNumber: 1,
			SourceID:       0,
		},
		FlowSets: flowsets,
	}
	return []IPFixMessage{msg}, nil
}
