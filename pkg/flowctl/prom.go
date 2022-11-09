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
		[]string{"ingressIfindex", "egressIfindex"},
	)
	// overflowBytes represents "total" of bytes couldn't be metered
	overflowBytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "overflow_bytes",
			Help:      "eBPF map overflow counter for each interfaces",
		},
		[]string{"ingressIfindex", "egressIfindex"},
	)
	// totalPkts represents "total" of pkts could be metered
	totalPkts = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "total_pkts",
			Help:      "eBPF map total counter for each interfaces",
		},
		[]string{"ingressIfindex", "egressIfindex"},
	)
	// totalBytes represents "total" of bytes could be metered
	totalBytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "total_bytes",
			Help:      "eBPF map total counter for each interfaces",
		},
		[]string{"ingressIfindex", "egressIfindex"},
	)
	// totalLatencyNanoseconds sums up the total time taken for the transfer.
	totalLatencyNanoseconds = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "total_latency_nanoseconds",
		},
		[]string{"ingressIfindex", "egressIfindex"},
	)
)

func threadMetricsExporter() error {
	go func() {
		for {
			stats, err := ebpfmap.GetStats()
			if err != nil {
				continue
			}
			for key, metrics := range stats {
				l := prometheus.Labels{
					"ingressIfindex": fmt.Sprintf("%d", key.IngressIfindex),
					"egressIfindex":  fmt.Sprintf("%d", key.EgressIfindex),
				}
				overflowPkts.With(l).Set(float64(metrics.OverflowPkts))
				overflowBytes.With(l).Set(float64(metrics.OverflowBytes))
				totalPkts.With(l).Set(float64(metrics.TotalPkts))
				totalBytes.With(l).Set(float64(metrics.TotalBytes))
				totalLatencyNanoseconds.With(l).Set(float64(metrics.TotalLatencyNanoseconds))
			}
			time.Sleep(time.Second)
		}
	}()
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9999", nil)
	return nil
}
