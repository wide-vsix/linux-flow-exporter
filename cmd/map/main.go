package main

import (
	"math/rand"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
)

var config struct {
	arg1 string
	arg2 string
}

func newCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "cmd",
		RunE: fn,
	}
	// cmd.Flags().StringVar(&config.arg1, "arg1", "def1", "this is arg1")
	// cmd.Flags().StringVar(&config.arg2, "arg2", "def2", "this is arg2")
	return cmd
}

func main() {
	rand.Seed(time.Now().UnixNano())
	if err := newCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func fn(cmd *cobra.Command, args []string) error {
	arr, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		panic(err)
	}

	pp.Println(arr)
	return nil
}
