package main

import (
	"math/rand"
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

func fn(cmd *cobra.Command, args []string) error {
	m, err := ebpf.NewMapFromID(ebpf.MapID(config.mapID))
	if err != nil {
		return err
	}
	pp.Println(m)

	return nil
}
