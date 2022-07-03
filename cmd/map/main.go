package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
	"github.com/wide-vsix/linux-flow-exporter/pkg/exporter"
	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

var config struct {
	mapID int
}

func newCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "cmd",
		RunE: fn,
	}
	cmd.Flags().IntVarP(&config.mapID, "mapid", "m", 4088, "ebpf map-id")
	return cmd
}

func main() {
	rand.Seed(time.Now().UnixNano())
	if err := newCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

type FlowKey struct {
	Ifindex uint32
	Saddr   uint32
	Daddr   uint32
	Sport   uint16
	Dport   uint16
	Proto   uint8
}

var (
	tmp = 0 // TODO(slankdev)
)

func (k FlowKey) String() string {
	ipaddr := int2ip(k.Daddr)
	return fmt.Sprintf("%s:%d", ipaddr.String(), k.Dport)
}

type FlowVal struct {
	Cnt uint32
}

type Flow struct {
	Key FlowKey
	Val FlowVal
}

func (f Flow) ToBuffer(buf *bytes.Buffer) error {
	msg := exporter.IPFixMessage{
		Header: exporter.IPFixHeader{
			VersionNumber:  10,
			SysupTime:      0x00002250,
			SequenceNumber: uint32(tmp),
			SourceID:       100,
		},
		FlowSets: []exporter.IPFixFlowSet{
			{
				FlowSetID: 1033,
				Flow: []exporter.IPFixFlow{
					{
						SourceIPv4Address:        util.BS32(f.Key.Saddr),
						DestinationIPv4Address:   util.BS32(f.Key.Daddr),
						SourceTransportPort:      f.Key.Sport,
						DestinationTransportPort: f.Key.Dport,
						// SourceTransportPort:      util.BS16((f.Key.Sport)),
						// DestinationTransportPort: util.BS16((f.Key.Dport)),
						ProtocolIdentifier: f.Key.Proto,
					},
				},
			},
		},
	}

	if err := msg.ToBuffer(buf); err != nil {
		return err
	}
	return nil
}

func fn(cmd *cobra.Command, args []string) error {
	if err := exporter.Do("./config.yaml"); err != nil {
		return err
	}
	tmp = 1

	for id := ebpf.MapID(0); ; {
		var err error
		id, err = ebpf.MapGetNextID(ebpf.MapID(id))
		if err != nil {
			break
		}

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		info, err := m.Info()
		if err != nil {
			return err
		}
		if info.Name != "flow_stats" || info.Type != ebpf.PerCPUHash {
			continue
		}

		key := FlowKey{}
		vals := []FlowVal{}
		entries := m.Iterate()
		for entries.Next(&key, &vals) {
			subval := FlowVal{0}
			for _, val := range vals {
				subval.Cnt += val.Cnt
			}
			fmt.Printf("%s -> %d\n", key.String(), subval.Cnt)

			f := Flow{
				Key: key,
				Val: subval,
			}

			addr := exporter.GetCollectorAddr()
			buf := &bytes.Buffer{}
			if err := f.ToBuffer(buf); err != nil {
				return err
			}
			if err := exporter.UdpTransmit(addr, buf); err != nil {
				return err
			}
			tmp++

			// DELETE
			if err := m.Delete(key); err != nil {
				return err
			}
		}
		if err := entries.Err(); err != nil {
			panic(err)
		}
	}

	println("bye...")
	return nil
}
