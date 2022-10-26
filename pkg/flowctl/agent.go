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
	"time"

	"github.com/spf13/cobra"
)

var cliOptAgent = struct {
	Config   string
	FlowFile string
}{}

func NewCommandAgent() *cobra.Command {
	cmd := &cobra.Command{
		Use: "agent",
		Run: func(cmd *cobra.Command, args []string) {
			go func() {
				slog.Info("metrics exporter thread is started")
				if err := threadMetricsExporter(); err != nil {
					panic(err)
				}
				slog.Info("metrics exporter thread is finished")
			}()
			go func() {
				slog.Info("flow exporter thread is started")
				if err := threadFlowExporter(); err != nil {
					panic(err)
				}
				slog.Info("flow exporter thread is finished")
			}()
			for {
				time.Sleep(1 * time.Second)
			}
		},
	}
	cmd.Flags().StringVarP(&cliOptAgent.Config, "config", "c", "./config.yaml",
		"Specifiy ipfix configuration")
	return cmd
}
