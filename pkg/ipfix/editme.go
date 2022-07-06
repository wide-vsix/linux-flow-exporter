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

	"github.com/cloudflare/goflow/decoders/netflow"
)

type Flow struct {
	FlowEndMilliseconds         uint64 `yaml:"FlowEndMilliseconds"`
	FlowStartMilliseconds       uint64 `yaml:"FlowStartMilliseconds"`
	FlowEndNanoseconds          uint64 `yaml:"FlowEndNanoseconds"`
	FlowStartNanoseconds        uint64 `yaml:"FlowStartNanoseconds"`
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

var ipfixfields = []fieldTableItem{
	{"FlowEndMilliseconds", netflow.IPFIX_FIELD_flowEndMilliseconds, 8},
	{"FlowStartMilliseconds", netflow.IPFIX_FIELD_flowStartMilliseconds, 8},
	{"FlowEndNanoseconds", netflow.IPFIX_FIELD_flowEndNanoseconds, 8},
	{"FlowStartNanoseconds", netflow.IPFIX_FIELD_flowStartNanoseconds, 8},
	{"OctetDeltaCount", netflow.IPFIX_FIELD_octetDeltaCount, 8},
	{"PacketDeltaCount", netflow.IPFIX_FIELD_packetDeltaCount, 8},
	{"IpVersion", netflow.IPFIX_FIELD_ipVersion, 1},
	{"IngressInterface", netflow.IPFIX_FIELD_ingressInterface, 4},
	{"EgressInterface", netflow.IPFIX_FIELD_egressInterface, 4},
	{"FlowDirection", netflow.IPFIX_FIELD_flowDirection, 1},
	{"SourceIPv4Address", netflow.IPFIX_FIELD_sourceIPv4Address, 4},
	{"DestinationIPv4Address", netflow.IPFIX_FIELD_destinationIPv4Address, 4},
	{"SourceTransportPort", netflow.IPFIX_FIELD_sourceTransportPort, 2},
	{"DestinationTransportPort", netflow.IPFIX_FIELD_destinationTransportPort, 2},
	{"TcpControlBits", netflow.IPFIX_FIELD_tcpControlBits, 1},
	{"ProtocolIdentifier", netflow.IPFIX_FIELD_protocolIdentifier, 1},
	{"IpClassOfService", netflow.IPFIX_FIELD_ipClassOfService, 1},
	{"SourceIPv4PrefixLength", netflow.IPFIX_FIELD_sourceIPv4PrefixLength, 1},
	{"DestinationIPv4PrefixLength", netflow.IPFIX_FIELD_destinationIPv4PrefixLength, 1},
	{"IpNextHopIPv4Address", netflow.IPFIX_FIELD_ipNextHopIPv4Address, 4},
	{"BgpSourceAsNumber", netflow.IPFIX_FIELD_bgpSourceAsNumber, 4},
	{"BgpDestinationAsNumber", netflow.IPFIX_FIELD_bgpDestinationAsNumber, 4},
	{"BgpNextHopIPv4Address", netflow.IPFIX_FIELD_bgpNextHopIPv4Address, 4},
	{"IcmpTypeCodeIPv4", netflow.IPFIX_FIELD_icmpTypeCodeIPv4, 2},
	{"MinimumTTL", netflow.IPFIX_FIELD_minimumTTL, 1},
	{"MaximumTTL", netflow.IPFIX_FIELD_maximumTTL, 1},
	{"FragmentIdentification", netflow.IPFIX_FIELD_fragmentIdentification, 4},
	{"VlanId", netflow.IPFIX_FIELD_vlanId, 2},
	{"FlowEndReason", netflow.IPFIX_FIELD_flowEndReason, 1},
	{"Dot1qVlanId", netflow.IPFIX_FIELD_dot1qVlanId, 2},
	{"Dot1qCustomerVlanId", netflow.IPFIX_FIELD_dot1qCustomerVlanId, 2},
}

func binaryWrite(fieldType uint16, buf *bytes.Buffer, flow *Flow) error {
	switch fieldType {
	case netflow.IPFIX_FIELD_flowEndMilliseconds:
		if err := binary.Write(buf, binary.BigEndian, &flow.FlowEndMilliseconds); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_flowStartMilliseconds:
		if err := binary.Write(buf, binary.BigEndian, &flow.FlowStartMilliseconds); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_flowEndNanoseconds:
		if err := binary.Write(buf, binary.BigEndian, &flow.FlowEndNanoseconds); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_flowStartNanoseconds:
		if err := binary.Write(buf, binary.BigEndian, &flow.FlowStartNanoseconds); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_octetDeltaCount:
		if err := binary.Write(buf, binary.BigEndian, &flow.OctetDeltaCount); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_packetDeltaCount:
		if err := binary.Write(buf, binary.BigEndian, &flow.PacketDeltaCount); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_ipVersion:
		if err := binary.Write(buf, binary.BigEndian, &flow.IpVersion); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_ingressInterface:
		if err := binary.Write(buf, binary.BigEndian, &flow.IngressInterface); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_egressInterface:
		if err := binary.Write(buf, binary.BigEndian, &flow.EgressInterface); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_flowDirection:
		if err := binary.Write(buf, binary.BigEndian, &flow.FlowDirection); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_sourceIPv4Address:
		if err := binary.Write(buf, binary.BigEndian, &flow.SourceIPv4Address); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_destinationIPv4Address:
		if err := binary.Write(buf, binary.BigEndian, &flow.DestinationIPv4Address); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_sourceTransportPort:
		if err := binary.Write(buf, binary.BigEndian, &flow.SourceTransportPort); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_destinationTransportPort:
		if err := binary.Write(buf, binary.BigEndian, &flow.DestinationTransportPort); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_tcpControlBits:
		if err := binary.Write(buf, binary.BigEndian, &flow.TcpControlBits); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_protocolIdentifier:
		if err := binary.Write(buf, binary.BigEndian, &flow.ProtocolIdentifier); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_ipClassOfService:
		if err := binary.Write(buf, binary.BigEndian, &flow.IpClassOfService); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_sourceIPv4PrefixLength:
		if err := binary.Write(buf, binary.BigEndian, &flow.SourceIPv4PrefixLength); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_destinationIPv4PrefixLength:
		if err := binary.Write(buf, binary.BigEndian, &flow.DestinationIPv4PrefixLength); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_ipNextHopIPv4Address:
		if err := binary.Write(buf, binary.BigEndian, &flow.IpNextHopIPv4Address); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_bgpSourceAsNumber:
		if err := binary.Write(buf, binary.BigEndian, &flow.BgpSourceAsNumber); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_bgpDestinationAsNumber:
		if err := binary.Write(buf, binary.BigEndian, &flow.BgpDestinationAsNumber); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_bgpNextHopIPv4Address:
		if err := binary.Write(buf, binary.BigEndian, &flow.BgpNextHopIPv4Address); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_icmpTypeCodeIPv4:
		if err := binary.Write(buf, binary.BigEndian, &flow.IcmpTypeCodeIPv4); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_minimumTTL:
		if err := binary.Write(buf, binary.BigEndian, &flow.MinimumTTL); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_maximumTTL:
		if err := binary.Write(buf, binary.BigEndian, &flow.MaximumTTL); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_fragmentIdentification:
		if err := binary.Write(buf, binary.BigEndian, &flow.FragmentIdentification); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_vlanId:
		if err := binary.Write(buf, binary.BigEndian, &flow.VlanId); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_flowEndReason:
		if err := binary.Write(buf, binary.BigEndian, &flow.FlowEndReason); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_dot1qVlanId:
		if err := binary.Write(buf, binary.BigEndian, &flow.Dot1qVlanId); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_dot1qCustomerVlanId:
		if err := binary.Write(buf, binary.BigEndian, &flow.Dot1qCustomerVlanId); err != nil {
			return err
		}
	}
	return nil
}
