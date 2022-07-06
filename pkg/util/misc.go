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

package util

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hairyhenderson/go-which"
	"github.com/zcalusic/sysinfo"
	"golang.org/x/mod/semver"
)

// GetClangVersion returns the version string of clang as semver-formant This
// string format can be compared by semver buitin package.
// ref: // https://pkg.go.dev/golang.org/x/mod/semver#Major
// clang may not work well because version output results may differ depending
// on the platform.
//
// DOCKER-TESTED: [centos:centos7, ubuntu:22.04, fedora:37]
func GetClangVersion() (string, error) {
	clangPath := which.Which("clang")
	if clangPath == "" {
		return "", nil
	}

	out, err := LocalExecutef("%s --version", clangPath)
	if err != nil {
		return "", err
	}

	// [EXAMPLE:centos 7]
	// $ clang --version
	// clang version 3.4.2 (tags/RELEASE_34/dot2-final)
	// Target: x86_64-redhat-linux-gnu
	// Thread model: posix
	//
	// [EXAMPLE:fedora 37]
	// $ clang --version
	// clang version 15.0.0 (Fedora 15.0.0-5.fc38)
	// Target: x86_64-redhat-linux-gnu
	// Thread model: posix
	// InstalledDir: /usr/bin
	//
	// [EXAMPLE:ubuntu 22.04]
	// $ clang --version
	// Ubuntu clang version 12.0.1-19ubuntu3
	// Target: x86_64-pc-linux-gnu
	// Thread model: posix
	// InstalledDir: /usr/bin

	lines := regexp.MustCompile("\r\n|\n").Split(out, -1)
	for _, line := range lines {
		if strings.Contains(line, "clang version") {
			words := strings.Fields(line)
			for idx := range words {
				if idx > 1 {
					if words[idx-2] == "clang" && words[idx-1] == "version" {
						subword := strings.Split(words[idx], "-")
						semverVal := fmt.Sprintf("v%s", subword[0])
						if !semver.IsValid(semverVal) {
							return "", fmt.Errorf("version unresolved")
						}
						return semverVal, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("version unresolved")
}

func GetIproute2Version() (string, string, error) {
	iproute2Path := which.Which("ip")
	if iproute2Path == "" {
		return "", "", nil
	}

	out, err := LocalExecutef("%s -V", iproute2Path)
	if err != nil {
		return "", "", err
	}

	// [EXAMPLE:centos 7]
	// $ ip -V
	// ip utility, iproute2-ss170501
	//
	// [EXAMPLE:ubuntu 20.04]
	// $ ip -V
	// ip utility, iproute2-5.18.0, libbpf 0.8.0
	//
	// [EXAMPLE: fedora 37]
	// $ ip -V
	// ip utility, iproute2-6.0.0, libbpf 0.8.0

	binVersion := "v0.0.0"
	libVersion := "v0.0.0"

	words := strings.Fields(out)
	for idx := range words {
		word := strings.Replace(words[idx], ",", "", -1)
		if strings.Contains(word, "iproute2-") {
			subwords := strings.Split(word, "-")
			if len(subwords) < 2 {
				return "", "", fmt.Errorf("invalid formant (%s)", word)
			}
			binVersionTmp := fmt.Sprintf("v%s", subwords[1])
			if semver.IsValid(binVersionTmp) {
				binVersion = binVersionTmp
			}
		}
		if idx > 1 && strings.Replace(words[idx-1], ",", "", -1) == "libbpf" {
			libVersion = fmt.Sprintf("v%s", word)
		}
	}

	return binVersion, libVersion, nil
}

func GetKernelVersion() (string, error) {
	var si sysinfo.SysInfo
	si.GetSysInfo()
	semverVal := fmt.Sprintf("v%s", strings.Split(si.Kernel.Release, "-")[0])
	if !semver.IsValid(semverVal) {
		return "", fmt.Errorf("invalid format (%s)", semverVal)
	}
	return semverVal, nil
}
