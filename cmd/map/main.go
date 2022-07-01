package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/k0kubun/pp"
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
	m, err := ebpf.NewMapFromID(ebpf.MapID(config.mapID))
	if err != nil {
		return err
	}
	pp.Println(m.Type().String())

	fmt.Println("---------")
	for id := ebpf.MapID(0); ; {
		var err error
		id, err = ebpf.MapGetNextID(ebpf.MapID(id))
		if err != nil {
			break
		}

		mm, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		info, err := mm.Info()
		if err != nil {
			return err
		}
		if info.Name != "flow_stats" {
			continue
		}

		fmt.Printf("%d\n", id)
	}
	fmt.Println("---------")

	info, err := m.Info()
	if err != nil {
		return err
	}
	pp.Println(info)

	key := FlowKey{}
	vals := []FlowVal{}
	entries := m.Iterate()
	for entries.Next(&key, &vals) {
		// fmt.Printf("-----\n")
		sum := uint32(0)
		for _, val := range vals {
			sum += val.Cnt
		}
		fmt.Printf("%s -> %d\n", key.String(), sum)
	}
	if err := entries.Err(); err != nil {
		panic(err)
	}

	println("bye...")
	return nil
}
