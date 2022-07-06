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
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"github.com/wide-vsix/linux-flow-exporter/pkg/ebpfmap"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// namespace is metrics's head strings
	namespace = "linux_flow_exporter"
	// overflowPkts represents "total" of pkts couldn't be metered
	overflowPkts = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "overflow_pkts",
			Help:      "eBPF map overflow counter for each interfaces",
		},
		[]string{"ifindex"},
	)
	// overflowBytes represents "total" of bytes couldn't be metered
	overflowBytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "overflow_bytes",
			Help:      "eBPF map overflow counter for each interfaces",
		},
		[]string{"ifindex"},
	)
	// totalPkts represents "total" of pkts could be metered
	totalPkts = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "total_pkts",
			Help:      "eBPF map total counter for each interfaces",
		},
		[]string{"ifindex"},
	)
	// totalBytes represents "total" of bytes could be metered
	totalBytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "total_bytes",
			Help:      "eBPF map total counter for each interfaces",
		},
		[]string{"ifindex"},
	)
)

func NewCommandPrometheus() *cobra.Command {
	cmd := &cobra.Command{
		Use: "prometheus",
	}
	cmd.AddCommand(NewCommandPrometheusExporter())
	return cmd
}

func NewCommandPrometheusExporter() *cobra.Command {
	cmd := &cobra.Command{
		Use: "exporter",
		RunE: func(cmd *cobra.Command, args []string) error {
			go func() {
				for {
					stats, err := ebpfmap.GetStats()
					if err != nil {
						continue
					}
					for ifindex, metrics := range stats {
						l := prometheus.Labels{
							"ifindex": fmt.Sprintf("%d", ifindex),
						}
						overflowPkts.With(l).Set(float64(metrics.OverflowPkts))
						overflowBytes.With(l).Set(float64(metrics.OverflowBytes))
						totalPkts.With(l).Set(float64(metrics.TotalPkts))
						totalBytes.With(l).Set(float64(metrics.TotalBytes))
					}
					time.Sleep(time.Second)
				}
			}()
			http.Handle("/metrics", promhttp.Handler())
			http.ListenAndServe(":9999", nil)
			return nil
		},
	}
	return cmd
}
