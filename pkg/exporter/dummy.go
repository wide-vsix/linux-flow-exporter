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

func dummyFlowSetData() IPFixFlowSet {
	return IPFixFlowSet{
		FlowSetID: 1024,
		Flow: []IPFixFlow{
			{
				FlowEndMilliseconds:      0x000001819e9d896b,
				FlowStartMilliseconds:    0x0000000000002118,
				OctetDeltaCount:          8482,
				PacketDeltaCount:         80,
				IpVersion:                4,
				IngressInterface:         0,
				EgressInterface:          0,
				FlowDirection:            0,
				SourceIPv4Address:        0x0a000005,
				DestinationIPv4Address:   0xcb000001,
				SourceTransportPort:      22,
				DestinationTransportPort: 63153,
				TcpControlBits:           0x18,
				ProtocolIdentifier:       6,
			},
			{
				FlowEndMilliseconds:      0x000001819e9d6565,
				FlowStartMilliseconds:    0x000001819e9d896b,
				OctetDeltaCount:          6732,
				PacketDeltaCount:         94,
				IpVersion:                4,
				IngressInterface:         0,
				EgressInterface:          0,
				FlowDirection:            0,
				SourceIPv4Address:        0xcb000001,
				DestinationIPv4Address:   0x0a000005,
				SourceTransportPort:      63153,
				DestinationTransportPort: 22,
				TcpControlBits:           0x18,
				ProtocolIdentifier:       6,
			},
		},
	}
}
