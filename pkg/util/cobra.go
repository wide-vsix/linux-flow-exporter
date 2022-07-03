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
	"os"

	"github.com/spf13/cobra"
)

func NewCmdCompletion(rootCmd *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [sub operation]",
		Short: "Display completion snippet",
		Args:  cobra.MinimumNArgs(1),
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "bash",
		Short: "Display bash-completion snippet",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			_ = rootCmd.GenBashCompletion(os.Stdout)
			cli := " "
			for _, arg := range os.Args {
				cli += arg + " "
			}
			fmt.Printf("#### \". <(%s)\" in your bashrc¥n", cli)
		},
		SilenceUsage: true,
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "zsh",
		Short: "Display zsh-completion snippet",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			_ = rootCmd.GenZshCompletion(os.Stdout)
		},
		SilenceUsage: true,
	})

	return cmd
}
