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

type Message struct {
	Header   Header
	FlowSets []FlowSet
}

type Header struct {
	VersionNumber  uint16
	SysupTime      uint32
	SequenceNumber uint32
	SourceID       uint32
}

type FlowSet struct {
	FlowSetID uint16       `yaml:"flowSetId"`
	Template  FlowTemplate `yaml:"template,omitempty"`
	Flow      []Flow       `yaml:"flow"`
}

type FlowTemplate struct {
	TemplateID uint16
	Fields     []FlowTemplateField
}

type FlowTemplateField struct {
	FieldType   uint16
	FieldLength uint16
}

type Flow struct {
	FlowEndMilliseconds         uint64 `yaml:"FlowEndMilliseconds"`
	FlowStartMilliseconds       uint64 `yaml:"FlowStartMilliseconds"`
	OctetDeltaCount             uint64 `yaml:"OctetDeltaCount"`
	PacketDeltaCount            uint64 `yaml:"PacketDeltaCount"`
	IpVersion                   uint8  `yaml:"IpVersion"`
	IngressInterface            uint32 `yaml:"IngressInterface"`
	EgressInterface             uint32 `yaml:"EgressInterface"`
	FlowDirection               uint8  `yaml:"FlowDirection"`
	SourceIPv4Address           uint32 `yaml:"SourceIPv4Address"`
	DestinationIPv4Address      uint32 `yaml:"DestinationIPv4Address"`
	SourceTransportPort         uint16 `yaml:"SourceTransportPort"`
	DestinationTransportPort    uint16 `yaml:"DestinationTransportPort"`
	TcpControlBits              uint8  `yaml:"TcpControlBits"`
	ProtocolIdentifier          uint8  `yaml:"ProtocolIdentifier"`
	IpClassOfService            uint8  `yaml:"IpClassOfService"`
	SourceIPv4PrefixLength      uint8  `yaml:"SourceIPv4PrefixLength"`
	DestinationIPv4PrefixLength uint8  `yaml:"DestinationIPv4PrefixLength"`
	IpNextHopIPv4Address        uint32 `yaml:"IpNextHopIPv4Address"`
	BgpSourceAsNumber           uint32 `yaml:"BgpSourceAsNumber"`
	BgpDestinationAsNumber      uint32 `yaml:"BgpDestinationAsNumber"`
	BgpNextHopIPv4Address       uint32 `yaml:"BgpNextHopIPv4Address"`
	IcmpTypeCodeIPv4            uint16 `yaml:"IcmpTypeCodeIPv4"`
	MinimumTTL                  uint8  `yaml:"MinimumTTL"`
	MaximumTTL                  uint8  `yaml:"MaximumTTL"`
	FragmentIdentification      uint32 `yaml:"FragmentIdentification"`
	VlanId                      uint16 `yaml:"VlanId"`
	FlowEndReason               uint8  `yaml:"FlowEndReason"`
	Dot1qVlanId                 uint16 `yaml:"Dot1qVlanId"`
	Dot1qCustomerVlanId         uint16 `yaml:"Dot1qCustomerVlanId"`
}
