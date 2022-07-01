package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
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
	Daddr uint32
	Dport uint16
}

func (k FlowKey) String() string {
	ipaddr := int2ip(k.Daddr)
	return fmt.Sprintf("%s:%d", ipaddr.String(), k.Dport)
}

type FlowVal struct {
	Cnt uint32
}

func fn(cmd *cobra.Command, args []string) error {
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
			sum := uint32(0)
			for _, val := range vals {
				sum += val.Cnt
			}
			fmt.Printf("%s -> %d\n", key.String(), sum)
		}
		if err := entries.Err(); err != nil {
			panic(err)
		}

		// TODO(slankdev): Update as 0
	}
	println("bye...")
	return nil
}
