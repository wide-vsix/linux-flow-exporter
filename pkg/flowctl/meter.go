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

package flowctl

import (
	"crypto/sha1"
	_ "embed"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wide-vsix/linux-flow-exporter/pkg/goroute2"
	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

func NewCommandMeter() *cobra.Command {
	cmd := &cobra.Command{
		Use: "meter",
	}
	cmd.AddCommand(NewCommandMeterAttach())
	cmd.AddCommand(NewCommandMeterDetach())
	cmd.AddCommand(NewCommandMeterStatus())
	return cmd
}

var cliOptMeter = struct {
	Attach struct {
		Force bool
		// Interface store the pair network namespace name and network device
		// name. When the default network namespace, we don't need to write
		// actual name of network namespace. These value are represented as
		// following syntax.
		//
		// EXAMPLE
		//   netns0:eth0
		//   netns1:eth1
		//   eth1       <--- default network namespace
		//   netns0:*   <--- all device in netns0
		Interface string
		Section   string
		Pref      uint
		Chain     uint
		Handle    uint
		// InterfaceMaxFlowLimit will be mapped on follow
		// #define INTERFACE_MAX_FLOW_LIMIT 6
		InterfaceMaxFlowLimit uint
		Dry                   bool
	}
	Detach struct {
		// Interface store the pair network namespace name and network device
		// name. When the default network namespace, we don't need to write
		// actual name of network namespace. These value are represented as
		// following syntax.
		//
		// EXAMPLE
		//   netns0:eth0
		//   netns1:eth1
		//   eth1       <--- default network namespace
		//   netns0:*   <--- all device in netns0
		Interface string
		Pref      uint
		Chain     uint
		Handle    uint
		Dry       bool
	}
}{}

func NewCommandMeterAttach() *cobra.Command {
	cmd := &cobra.Command{
		Use: "attach",
		RunE: func(cmd *cobra.Command, args []string) error {
			netns, device, err := parseInterface(cliOptMeter.Attach.Interface)
			if err != nil {
				return err
			}

			links, err := goroute2.ListLinkMatch(netns, device)
			if err != nil {
				return err
			}

			for _, link := range links {
				bc, err := NewFlowMeterByteCode(netns, link.Ifname,
					uint16(cliOptMeter.Attach.InterfaceMaxFlowLimit))
				if err != nil {
					return err
				}

				// Enable cls act if it's disabled
				if err := goroute2.EnsureClsactEnabled(netns, link.Ifname); err != nil {
					return err
				}

				attached, bpfname, err := bpfIsAttached(netns, link.Ifname,
					cliOptMeter.Attach.Pref, cliOptMeter.Attach.Chain,
					cliOptMeter.Attach.Handle)
				if err != nil {
					return err
				}

				changed := false
				requestAttach := false

				if attached {
					same, err := bc.SameDigest(bpfname)
					if err != nil {
						return err
					}
					if same {
						// donothing
					} else {
						if err := bpfDetach(netns, link.Ifname, cliOptMeter.Attach.Pref,
							cliOptMeter.Attach.Chain, cliOptMeter.Attach.Handle,
							cliOptMeter.Attach.Dry); err != nil {
							return err
						}
						changed = true
						requestAttach = true
					}
				} else {
					requestAttach = true
				}

				if requestAttach {
					if err := bpfAttach(netns, link.Ifname, cliOptMeter.Attach.Pref,
						cliOptMeter.Attach.Chain, cliOptMeter.Attach.Handle, bc,
						cliOptMeter.Attach.Section, cliOptMeter.Attach.Dry); err != nil {
						return err
					}
					changed = true
				}

				changedStr := " (unchanged)"
				if changed {
					changedStr = " (changed)"
				}
				fmt.Printf("%s:%s%s\n", netns, link.Ifname, changedStr)
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&cliOptMeter.Attach.Dry, "dry", false, "Dry run mode")
	cmd.Flags().BoolVarP(&cliOptMeter.Attach.Force, "force", "f", false,
		"Force current ebpf bytecode when the byte code is different."+
			"It's not replace when the byte code is not different")
	cmd.Flags().StringVarP(&cliOptMeter.Attach.Interface, "interface", "i", "",
		"Target network namespace and device name (NETNS:DEV or DEV)")
	cmd.Flags().StringVar(&cliOptMeter.Attach.Section, "section",
		"tc-egress", "Target section name of bpf byte code")
	cmd.Flags().UintVar(&cliOptMeter.Attach.Pref, "pref", 100,
		"Target preference idx of tc-egress")
	cmd.Flags().UintVar(&cliOptMeter.Attach.Chain, "chain", 0,
		"Target chain idx of tc-egress")
	cmd.Flags().UintVar(&cliOptMeter.Attach.Handle, "handle", 1,
		"Target handle idx of chain of tc-egress")
	cmd.Flags().UintVarP(&cliOptMeter.Attach.InterfaceMaxFlowLimit,
		"interface-max-flow-limit", "l", 6,
		"eBPF map max size for each interfaces")
	return cmd
}

func NewCommandMeterDetach() *cobra.Command {
	cmd := &cobra.Command{
		Use: "detach",
		RunE: func(cmd *cobra.Command, args []string) error {
			netns, device, err := parseInterface(cliOptMeter.Detach.Interface)
			if err != nil {
				return err
			}

			netnsPreCmd := ""
			if netns != "" {
				netnsPreCmd = fmt.Sprintf("ip netns exec %s", netns)
			}

			links, err := goroute2.ListLinkMatch(netns, device)
			if err != nil {
				return err
			}

			for _, link := range links {
				changed := false

				// Delete rule if exist
				rules, err := goroute2.ListTcFilterRules(netns, link.Ifname)
				if err != nil {
					return err
				}
				for _, rule := range rules {
					if rule.Pref == cliOptMeter.Detach.Pref &&
						rule.Chain == cliOptMeter.Detach.Chain &&
						rule.Options.Handle == fmt.Sprintf("0x%x", cliOptMeter.Detach.Handle) {
						if !cliOptMeter.Detach.Dry {
							if _, err := util.LocalExecutef("%s tc filter del dev %s egress "+
								"pref %d chain %d handle 0x%x bpf", netnsPreCmd, link.Ifname,
								cliOptMeter.Detach.Pref, cliOptMeter.Detach.Chain,
								cliOptMeter.Detach.Handle,
							); err != nil {
								return err
							}
						}
						changed = true
					}
				}

				tmp := netns
				if tmp == "" {
					tmp = "DEFAULT"
				}
				changedStr := " (unchanged)"
				if changed {
					changedStr = " (changed)"
				}
				fmt.Printf("%s:%s%s\n", tmp, link.Ifname, changedStr)
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&cliOptMeter.Detach.Dry, "dry", false, "Dry run mode")
	cmd.Flags().StringVarP(&cliOptMeter.Detach.Interface, "interface", "i", "",
		"Target network namespace and device name (NETNS:DEV or DEV)")
	cmd.Flags().UintVar(&cliOptMeter.Detach.Pref, "pref", 100,
		"Target preference idx of tc-egress")
	cmd.Flags().UintVar(&cliOptMeter.Detach.Chain, "chain", 0,
		"Target chain idx of tc-egress")
	cmd.Flags().UintVar(&cliOptMeter.Detach.Handle, "handle", 1,
		"Target handle idx of chain of tc-egress")
	return cmd
}

func NewCommandMeterStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use: "status",
		RunE: func(cmd *cobra.Command, args []string) error {
			netnsList, err := goroute2.ListNetns()
			if err != nil {
				return err
			}

			// Non-root netns
			for _, netns := range netnsList {
				links, err := goroute2.ListLink(netns)
				if err != nil {
					return err
				}
				for _, link := range links {
					if link.Ifname != "lo" {
						name, err := getTcEbpfByteCode(netns, link.Ifname)
						if err != nil {
							return err
						}
						if name == "" {
							name = "<n/a>"
						}
						fmt.Printf("%s:%s = %s\n", netns, link.Ifname, name)
					}
				}
			}

			// Root netns (default)
			links, err := goroute2.ListLink("")
			if err != nil {
				return err
			}
			for _, link := range links {
				if link.Ifname != "lo" {
					name, err := getTcEbpfByteCode("", link.Ifname)
					if err != nil {
						return err
					}
					if name == "" {
						name = "<n/a>"
					}
					fmt.Printf("DEFAULT:%s = %s\n", link.Ifname, name)
				}
			}

			return nil
		},
	}
	return cmd
}

const (
	meterDir = "/var/run/flowctl"
)

type FlowMeterByteCode struct {
	// AttachedTime indicates when the tc filter was created.
	AttachedTime time.Time
	// Digest is a Hash of Code. It is used to determine if the Bytecode
	// currently in use needs to be changed.
	// Code contains the source code of the BPF program. This is useful
	// to check the differences between versions, since the table entry
	// size is not embedded.
	Digest string
	// NetnsName indicates network namespace name like ns0, ns1, etc...
	// It's not include device information.
	// Currently we are expecting the name is not include special characters,
	// like .,:/-?
	NetnsName string
	// DeviceName indicates network interface name like eth0, eth1, etc...
	// It's not include namespace information
	// It is possible to include special characters like .-@
	DeviceName string
	// InterfaceMaxFlowLimit will be mapped on follow
	// #define INTERFACE_MAX_FLOW_LIMIT 6
	InterfaceMaxFlowLimit uint16
}

func NewFlowMeterByteCode(netns, device string, lim uint16) (*FlowMeterByteCode, error) {
	if err := os.MkdirAll(meterDir, os.ModePerm); err != nil {
		return nil, err
	}

	if netns == "" {
		netns = "DEFAULT"
	}

	hash := sha1.New()
	hash.Write(filterBpfFileContent)
	hashval := hash.Sum(nil)
	hashstr := fmt.Sprintf("%x", hashval)

	bc := &FlowMeterByteCode{
		AttachedTime:          time.Now(),
		Digest:                hashstr,
		NetnsName:             netns,
		DeviceName:            device,
		InterfaceMaxFlowLimit: lim,
	}

	obj := bc.EncodeToFilename()
	src := fmt.Sprintf("%s/scode.%s.bpf.c", meterDir, hashstr)
	if err := os.WriteFile(src, filterBpfFileContent, 0644); err != nil {
		return nil, err
	}

	// Build
	if _, err := util.LocalExecutef(
		"clang -target bpf -O3 -g -DINTERFACE_MAX_FLOW_LIMIT=%d -c %s -o %s",
		lim, src, obj); err != nil {
		return nil, err
	}

	return bc, nil
}

func (v FlowMeterByteCode) EncodeToFilename() string {
	// /var/run/flowctl/{timestamp}.{digest}.{netns}.{device}.{limit}.bpf.o
	return fmt.Sprintf("%s/bcode.%016x.%s.%s.%s.%04x.bpf.o", meterDir,
		v.AttachedTime.Unix(), v.Digest, v.NetnsName, v.DeviceName,
		v.InterfaceMaxFlowLimit)
}

func DecodeFromBpfName(bpfname string) (*FlowMeterByteCode, error) {
	words := strings.Split(bpfname, ":")
	if len(words) != 2 {
		return nil, fmt.Errorf("SameDigest: invalid format (%s)", bpfname)
	}
	fullpath := fmt.Sprintf("%s/%s", meterDir, words[0])
	bc, err := DecodeFromFullpath(fullpath)
	if err != nil {
		return nil, err
	}
	return bc, nil
}

func DecodeFromFullpath(s string) (*FlowMeterByteCode, error) {
	v := &FlowMeterByteCode{}
	words0 := strings.Split(s, "/")
	if len(words0) != 5 {
		return nil, fmt.Errorf("DecodeFromFullpath: invalid format (%s) line1", s)
	}
	words := strings.Split(words0[4], ".")
	if len(words) != 8 {
		return nil, fmt.Errorf("DecodeFromFullpath: invalid format (%s) line2", s)
	}
	tsval, err := strconv.ParseInt(words[1], 16, 64)
	if err != nil {
		return nil, err
	}
	limitval, err := strconv.ParseUint(words[5], 16, 16)
	if err != nil {
		return nil, err
	}
	v.AttachedTime = time.Unix(tsval, 0)
	v.Digest = words[2]
	v.NetnsName = words[3]
	v.DeviceName = words[4]
	v.InterfaceMaxFlowLimit = uint16(limitval)
	return v, nil
}

func (v FlowMeterByteCode) SameDigest(bpfname string) (bool, error) {
	// e3cf4890517434e09918631b6ffca82d7002fa45.bpf.ns0.eth1.6.o:[tc-egress]
	bc, err := DecodeFromBpfName(bpfname)
	if err != nil {
		return false, err
	}
	return bc.Digest == v.Digest, nil
}

func bpfIsAttached(netns, device string,
	pref, chain, handle uint) (bool, string, error) {
	rules, err := goroute2.ListTcFilterRules(netns, device)
	if err != nil {
		return false, "", err
	}
	for _, rule := range rules {
		if rule.Pref == cliOptMeter.Attach.Pref &&
			rule.Chain == cliOptMeter.Attach.Chain &&
			rule.Options.Handle == fmt.Sprintf("0x%x", cliOptMeter.Attach.Handle) {
			return true, rule.Options.BpfName, nil
		}
	}
	return false, "", nil
}

func bpfDetach(netns, device string, pref, chain, handle uint, dry bool) error {
	netnsPreCmd := ""
	if netns != "" {
		netnsPreCmd = fmt.Sprintf("ip netns exec %s", netns)
	}
	if !dry {
		if _, err := util.LocalExecutef("%s tc filter del dev %s egress "+
			"pref %d chain %d handle 0x%x bpf",
			netnsPreCmd, device, pref, chain, handle); err != nil {
			return err
		}
	}
	return nil
}

func bpfAttach(netns, device string, pref, chain, handle uint,
	bc *FlowMeterByteCode, section string, dry bool) error {
	netnsPreCmd := ""
	if netns != "" {
		netnsPreCmd = fmt.Sprintf("ip netns exec %s", netns)
	}
	if !dry {
		if _, err := util.LocalExecutef("%s tc filter add dev %s egress "+
			"pref %d chain %d handle 0x%x bpf obj %s section %s", netnsPreCmd, device,
			pref, chain, handle, bc.EncodeToFilename(), section); err != nil {
			return err
		}
	}
	return nil
}
