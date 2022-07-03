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

import "github.com/spf13/cobra"

var cliOptIpfix = struct {
	Config string
}{}

func NewCommandIpfix() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "ipfix",
		RunE: fnIpfix,
	}
	cmd.Flags().StringVarP(&cliOptIpfix.Config, "config", "c", "./config.yaml",
		"Specifiy ipfix configuration")
	return cmd
}

func fnIpfix(cmd *cobra.Command, args []string) error {
	// TODO(slankdev): implement me
	return nil
}
