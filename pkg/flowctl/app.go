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
	_ "embed"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"

	"github.com/wide-vsix/linux-flow-exporter/pkg/goroute2"
	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

//go:embed data/filter.bpf.c
var filterBpfFileContent []byte

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "flowctl",
	}
	cmd.AddCommand(NewCommandDump())
	cmd.AddCommand(NewCommandFlush())
	cmd.AddCommand(NewCommandIpfix())
	cmd.AddCommand(NewCommandMeter())
	cmd.AddCommand(NewCommandDependencyCheck())
	cmd.AddCommand(NewCommandEbpf())
	cmd.AddCommand(NewCommandAgent())
	cmd.AddCommand(util.NewCommandVersion())
	cmd.AddCommand(util.NewCmdCompletion(cmd))
	return cmd
}

type SystemCapability struct {
	ClangVersionCurrent         string
	ClangVersionExpected        string
	KernelVersionCurrent        string
	KernelVersionExpected       string
	Iproute2binVersionCurrent   string
	Iproute2binVersionExpected  string
	Iproute2lbpfVersionCurrent  string
	Iproute2lbpfVersionExpected string
}

func (sc *SystemCapability) Get() error {
	var err error
	sc.ClangVersionExpected = "v10.0.0"
	sc.KernelVersionExpected = "v5.4.0"
	sc.Iproute2binVersionExpected = "v5.4.0"
	sc.Iproute2lbpfVersionExpected = "v0.8.0"
	sc.ClangVersionCurrent, err = util.GetClangVersion()
	if err != nil {
		return err
	}
	sc.KernelVersionCurrent, err = util.GetKernelVersion()
	if err != nil {
		return err
	}
	sc.Iproute2binVersionCurrent, sc.Iproute2lbpfVersionCurrent, err = util.GetIproute2Version()
	if err != nil {
		return err
	}
	return nil
}

func (sc SystemCapability) Capable() bool {
	if semver.Compare(sc.ClangVersionCurrent, sc.ClangVersionExpected) < 0 {
		return false
	}
	if semver.Compare(sc.KernelVersionCurrent, sc.KernelVersionExpected) < 0 {
		return false
	}
	if semver.Compare(sc.Iproute2binVersionCurrent, sc.Iproute2binVersionExpected) < 0 {
		return false
	}
	if semver.Compare(sc.Iproute2lbpfVersionCurrent, sc.Iproute2lbpfVersionExpected) < 0 {
		return false
	}
	return true
}

func (sc SystemCapability) DumpToStdout() {
	validate := func(currentVersion, expectedVersion string) string {
		if currentVersion == "" {
			return "NOT-INSTALLED"
		} else {
			if semver.Compare(currentVersion, expectedVersion) >= 0 {
				return "VALID"
			} else {
				return "INVALID"
			}
		}
	}

	// Verify clang version
	fmt.Printf("clang version (expect %s): %s (%s)\n",
		sc.ClangVersionExpected, sc.ClangVersionCurrent,
		validate(sc.ClangVersionCurrent, sc.ClangVersionExpected))

	// Verify kernel version
	fmt.Printf("kernel version (expect %s): %s (%s)\n",
		sc.KernelVersionExpected, sc.KernelVersionCurrent,
		validate(sc.KernelVersionCurrent, sc.KernelVersionExpected))

	// Verify iproute2 and its libbpf version
	fmt.Printf("iproute2 binary version (expect %s): %s (%s)\n",
		sc.Iproute2binVersionExpected, sc.Iproute2binVersionCurrent,
		validate(sc.Iproute2binVersionCurrent, sc.Iproute2binVersionExpected))
	fmt.Printf("iproute2 libbpf version (expect %s): %s (%s)\n",
		sc.Iproute2lbpfVersionExpected, sc.Iproute2lbpfVersionCurrent,
		validate(sc.Iproute2lbpfVersionCurrent, sc.Iproute2lbpfVersionExpected))
}

func NewCommandDependencyCheck() *cobra.Command {
	cmd := &cobra.Command{
		Use: "dependency-check",
		RunE: func(cmd *cobra.Command, args []string) error {
			sc := SystemCapability{}
			if err := sc.Get(); err != nil {
				return err
			}
			sc.DumpToStdout()
			return nil
		},
	}
	return cmd
}

func NewCommandEbpf() *cobra.Command {
	cmd := &cobra.Command{
		Use: "ebpf",
	}
	cmd.AddCommand(NewCommandEbpfCodeDump())
	return cmd
}

func NewCommandEbpfCodeDump() *cobra.Command {
	cmd := &cobra.Command{
		Use: "code-dump",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("%s\n", string(filterBpfFileContent))
			return nil
		},
	}
	return cmd
}

func getTcEbpfByteCode(netns, dev string) (string, error) {
	clsActIsEnabled, err := goroute2.ClsActIsEnabled(netns, dev)
	if err != nil {
		return "", err
	}
	if clsActIsEnabled {
		rules, err := goroute2.ListTcFilterRules(netns, dev)
		if err != nil {
			return "", err
		}
		for _, rule := range rules {
			if rule.Kind == "bpf" && rule.Options.BpfName != "" {
				return rule.Options.BpfName, nil
			}
		}
	}
	return "", nil
}

func parseInterface(s string) (netns string, device string, err error) {
	if s == "" {
		return "", "", fmt.Errorf("interface is not specified")
	}
	words := strings.Split(s, ":")
	switch {
	case len(words) == 2:
		return words[0], words[1], nil
	case len(words) == 1:
		return "", words[0], nil
	default:
		return "", "", fmt.Errorf("invalid formant (%s)", s)
	}
}
