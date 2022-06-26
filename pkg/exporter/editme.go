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

	"github.com/cloudflare/goflow/decoders/netflow"
)

type IPFixFlow struct {
	FlowEndMilliseconds      uint64
	FlowStartMilliseconds    uint64
	OctetDeltaCount          uint64
	PacketDeltaCount         uint64
	IpVersion                uint8
	IngressInterface         uint32
	EgressInterface          uint32
	FlowDirection            uint8
	SourceIPv4Address        uint32
	DestinationIPv4Address   uint32
	SourceTransportPort      uint16
	DestinationTransportPort uint16
	TcpControlBits           uint8
	ProtocolIdentifier       uint8
}

var ipfixfields = []fieldTableItem{
	{"FlowEndMilliseconds", netflow.IPFIX_FIELD_flowEndMilliseconds, 8},
	{"FlowStartMilliseconds", netflow.IPFIX_FIELD_flowStartMilliseconds, 8},
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
}

func binaryWrite(fieldType uint16, buf *bytes.Buffer, flow *IPFixFlow) error {
	switch fieldType {
	case netflow.IPFIX_FIELD_flowEndMilliseconds:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.FlowEndMilliseconds); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_flowStartMilliseconds:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.FlowStartMilliseconds); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_octetDeltaCount:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.OctetDeltaCount); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_packetDeltaCount:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.PacketDeltaCount); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_ipVersion:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.IpVersion); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_ingressInterface:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.IngressInterface); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_egressInterface:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.EgressInterface); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_flowDirection:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.FlowDirection); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_sourceIPv4Address:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.SourceIPv4Address); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_destinationIPv4Address:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.DestinationIPv4Address); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_sourceTransportPort:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.SourceTransportPort); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_destinationTransportPort:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.DestinationTransportPort); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_tcpControlBits:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.TcpControlBits); err != nil {
			return err
		}
	case netflow.IPFIX_FIELD_protocolIdentifier:
		if err := binary.Write(buf, binary.BigEndian,
			&flow.ProtocolIdentifier); err != nil {
			return err
		}
	}
	return nil
}
