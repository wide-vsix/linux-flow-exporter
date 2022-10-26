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
		Override bool
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

			// Ensure bpf file content
			if err := os.MkdirAll("/var/run/flowctl", os.ModePerm); err != nil {
				return err
			}
			hash := sha1.New()
			hash.Write(filterBpfFileContent)
			hashval := hash.Sum(nil)
			fileprefix := fmt.Sprintf("/var/run/flowctl/%x.bpf", hashval)
			if err := os.WriteFile(fmt.Sprintf("%s.c", fileprefix),
				filterBpfFileContent, 0644); err != nil {
				return err
			}

			filterBpfObjectPath := fmt.Sprintf("%s.%s.%s.%d.o", fileprefix,
				netns, device, cliOptMeter.Attach.InterfaceMaxFlowLimit)

			// Build
			if _, err := util.LocalExecutef(
				"clang -target bpf -O3 -g -DINTERFACE_MAX_FLOW_LIMIT=%d -c %s.c -o %s",
				cliOptMeter.Attach.InterfaceMaxFlowLimit,
				fileprefix, filterBpfObjectPath,
			); err != nil {
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
				overriden := false
				changed := false

				// Enable cls act if it's disabled
				clsActIsEnabled, err := goroute2.ClsActIsEnabled(netns, link.Ifname)
				if err != nil {
					return err
				}
				if !clsActIsEnabled {
					if !cliOptMeter.Attach.Dry {
						if _, err := util.LocalExecutef("%s tc qdisc add dev %s clsact",
							netnsPreCmd, link.Ifname); err != nil {
							return err
						}
					}
					changed = true
				}

				// Delete existing rule
				if cliOptMeter.Attach.Override {
					rules, err := goroute2.ListTcFilterRules(netns, link.Ifname)
					if err != nil {
						return err
					}
					for _, rule := range rules {
						if rule.Pref == cliOptMeter.Attach.Pref &&
							rule.Chain == cliOptMeter.Attach.Chain &&
							rule.Options.Handle == fmt.Sprintf("0x%x", cliOptMeter.Attach.Handle) {

							if !cliOptMeter.Attach.Dry {
								if _, err := util.LocalExecutef("%s tc filter del dev %s egress "+
									"pref %d chain %d handle 0x%x bpf", netnsPreCmd, link.Ifname,
									cliOptMeter.Attach.Pref, cliOptMeter.Attach.Chain,
									cliOptMeter.Attach.Handle,
								); err != nil {
									return err
								}
							}
							changed = true
							overriden = true
						}
					}
				}

				if !cliOptMeter.Attach.Dry {
					// Install rule
					//
					// [EXAMPLE]
					// tc filter add dev eth1 egress \
					//   pref 100 chain 10 handle 0xA \
					//   bpf obj ./cmd/ebpflow/filter.bpf.o section tc-egress
					if _, err := util.LocalExecutef("%s tc filter add dev %s egress "+
						"pref %d chain %d handle 0x%x "+
						"bpf obj %s section %s", netnsPreCmd, link.Ifname,
						cliOptMeter.Attach.Pref, cliOptMeter.Attach.Chain,
						cliOptMeter.Attach.Handle,
						filterBpfObjectPath,
						cliOptMeter.Attach.Section,
					); err != nil {
						return err
					}
				}
				changed = true

				fmt.Printf("%s:%s (changed=%v, overriden=%v)\n", netns, link.Ifname,
					changed, overriden)
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&cliOptMeter.Attach.Dry, "dry", false, "Dry run mode")
	cmd.Flags().BoolVarP(&cliOptMeter.Attach.Override, "override", "o", true,
		"Override current ebpf bytecode")
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
				fmt.Printf("%s:%s (changed=%v)\n", tmp, link.Ifname, changed)
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
						fmt.Printf("%s.%s: %s\n", netns, link.Ifname, name)
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
					fmt.Printf("DEFAULT.%s: %s\n", link.Ifname, name)
				}
			}

			return nil
		},
	}
	return cmd
}
