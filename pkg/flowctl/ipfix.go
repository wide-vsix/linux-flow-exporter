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
	"bytes"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/wide-vsix/linux-flow-exporter/pkg/ebpfmap"
	"github.com/wide-vsix/linux-flow-exporter/pkg/ipfix"
	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

var cliOptIpfix = struct {
	Config   string
	FlowFile string
}{}

var slog logr.Logger

func init() {
	cfg := zap.NewProductionConfig()
	zapLog, _ := cfg.Build()
	slog = zapr.NewLogger(zapLog)
}

func NewCommandIpfix() *cobra.Command {
	cmd := &cobra.Command{
		Use: "ipfix",
	}
	cmd.AddCommand(NewCommandIpfixTemplate())
	cmd.AddCommand(NewCommandIpfixDump())
	return cmd
}

func NewCommandIpfixTemplate() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "file",
		RunE: fnIpfixTemplate,
	}
	cmd.Flags().StringVarP(&cliOptIpfix.Config, "config", "c", "./config.yaml",
		"Specifiy ipfix configuration")
	cmd.Flags().StringVarP(&cliOptIpfix.FlowFile, "flow", "f", "./flow.yaml",
		"Specifiy ipfix flow file")
	return cmd
}

func fnIpfixTemplate(cmd *cobra.Command, args []string) error {
	config := ipfix.Config{}
	if err := util.FileUnmarshalAsYaml(cliOptIpfix.Config, &config); err != nil {
		return err
	}
	flow := ipfix.FlowFile{}
	if err := util.FileUnmarshalAsYaml(cliOptIpfix.FlowFile, &flow); err != nil {
		return err
	}

	// Transmit Flow Template Message
	buf1 := bytes.Buffer{}
	templateMessage, err := config.ToFlowTemplatesMessage()
	if err != nil {
		return err
	}
	templateMessage.Header.SysupTime = 0      // TODO
	templateMessage.Header.SequenceNumber = 0 // TODO
	templateMessage.Header.SourceID = 0       // TODO
	if err := templateMessage.Write(&buf1); err != nil {
		return err
	}
	for _, o := range config.Outputs {
		if !o.Valid() {
			return fmt.Errorf("invalid config")
		}
		if o.Collector != nil {
			if err := util.UdpTransmit(o.Collector.LocalAddress,
				o.Collector.RemoteAddress, &buf1); err != nil {
				return err
			}
		}
	}

	// Transmit Flow Data Message
	flowDataMessages, err := flow.ToFlowDataMessages(&config, 0)
	if err != nil {
		return err
	}
	for _, flowDataMessage := range flowDataMessages {
		buf2 := bytes.Buffer{}
		if err := flowDataMessage.Write(&buf2, &config); err != nil {
			return err
		}
		for _, o := range config.Outputs {
			if !o.Valid() {
				return fmt.Errorf("invalid config")
			}
			if o.Collector != nil {
				if err := util.UdpTransmit(o.Collector.LocalAddress,
					o.Collector.RemoteAddress, &buf2); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func NewCommandIpfixDump() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "dump",
		RunE: fnIpfixDump,
	}
	cmd.Flags().StringVarP(&cliOptIpfix.Config, "config", "c", "./config.yaml",
		"Specifiy ipfix configuration")
	return cmd
}

func fnIpfixDump(cmd *cobra.Command, args []string) error {
	config := ipfix.Config{}
	if err := util.FileUnmarshalAsYaml(cliOptIpfix.Config, &config); err != nil {
		return err
	}

	// template
	buf1 := bytes.Buffer{}
	templateMessage, err := config.ToFlowTemplatesMessage()
	if err != nil {
		return err
	}
	templateMessage.Header.SysupTime = 0 // TODO
	templateMessage.Header.SysupTime = uint32(util.TimeNow())
	templateMessage.Header.SequenceNumber = 0 // TODO
	templateMessage.Header.SourceID = 0       // TODO
	if err := templateMessage.Write(&buf1); err != nil {
		return err
	}
	for _, o := range config.Outputs {
		if !o.Valid() {
			return fmt.Errorf("invalid config")
		}
		if o.Collector != nil {
			if err := util.UdpTransmit(o.Collector.LocalAddress,
				o.Collector.RemoteAddress, &buf1); err != nil {
				return err
			}
		}
	}

	// flowdata
	ebpfFlows, err := ebpfmap.Dump()
	if err != nil {
		return err
	}
	//flow, err := T(ebpfFlows)
	flow, err := ebpfmap.ToIpfixFlowFile(ebpfFlows)
	if err != nil {
		return err
	}

	flowDataMessages, err := flow.ToFlowDataMessages(&config, 0)
	if err != nil {
		return err
	}
	for _, flowDataMessage := range flowDataMessages {
		flowDataMessage.Header.SysupTime = uint32(util.TimeNow())
		buf2 := bytes.Buffer{}
		if err := flowDataMessage.Write(&buf2, &config); err != nil {
			return err
		}
		for _, o := range config.Outputs {
			if !o.Valid() {
				return fmt.Errorf("invalid config")
			}
			if o.Log != nil {
				if err := FlowOutputLog(ebpfFlows, o.Log.File, *o.Log); err != nil {
					return err
				}
			}
			if o.Collector != nil {
				if err := util.UdpTransmit(o.Collector.LocalAddress,
					o.Collector.RemoteAddress, &buf2); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func threadFlowExporter() error {
	config := ipfix.Config{}
	if err := util.FileUnmarshalAsYaml(cliOptAgent.Config, &config); err != nil {
		return err
	}

	// template
	buf1 := bytes.Buffer{}
	templateMessage, err := config.ToFlowTemplatesMessage()
	if err != nil {
		return err
	}
	templateMessage.Header.SysupTime = 0 // TODO
	templateMessage.Header.SysupTime = uint32(util.TimeNow())
	templateMessage.Header.SequenceNumber = 0 // TODO
	templateMessage.Header.SourceID = 0       // TODO
	if err := templateMessage.Write(&buf1); err != nil {
		return err
	}
	for _, o := range config.Outputs {
		if !o.Valid() {
			return fmt.Errorf("invalid config")
		}
		if o.Collector != nil {
			if err := util.UdpTransmit(o.Collector.LocalAddress,
				o.Collector.RemoteAddress, &buf1); err != nil {
				return err
			}
		}
	}

	tickerFinished := time.NewTicker(time.Duration(config.TimerFinishedDrainSeconds) * time.Second)
	ticketForce := time.NewTicker(time.Duration(config.TimerForceDrainSeconds) * time.Second)
	tickerForTemplateFlush := time.NewTicker(time.Duration(config.TimerTemplateFlushSeconds) * time.Second)
	perfEvent, err := ebpfmap.StartReader()
	if err != nil {
		return err
	}
	defer close(perfEvent)

	for {
		select {
		case pe := <-perfEvent:
			slog.Info("map is full", "mapfd", pe.MapID, "ifindex", pe.Ifindex())
			ebpfFlows, err := ebpfmap.Dump()
			if err != nil {
				return err
			}
			if len(ebpfFlows) == 0 {
				continue
			}

			before := time.Now()
			nFlows, err := flushCaches(config)
			if err != nil {
				return err
			}
			if err := ebpfmap.DeleteAll(); err != nil {
				return err
			}
			slog.Info("force drain current flows", "usec",
				time.Since(before).Microseconds(), "nFlows", nFlows)

		case <-tickerFinished.C:
			ebpfFlows, err := ebpfmap.Dump()
			if err != nil {
				return err
			}
			if len(ebpfFlows) == 0 {
				continue
			}

			before := time.Now()
			nFlows, err := flushCachesFinished(config)
			if err != nil {
				return err
			}
			if nFlows > 0 {
				slog.Info("drain finished flows", "usec",
					time.Since(before).Microseconds(), "nFlows", nFlows)
			}
			if err := ebpfmap.DeleteFinished(); err != nil {
				return err
			}

		case <-ticketForce.C:
			ebpfFlows, err := ebpfmap.Dump()
			if err != nil {
				return err
			}
			if len(ebpfFlows) == 0 {
				continue
			}

			before := time.Now()
			nFlows, err := flushCaches(config)
			if err != nil {
				return err
			}
			if err := ebpfmap.DeleteAll(); err != nil {
				return err
			}
			slog.Info("force drain current flows", "usec",
				time.Since(before).Microseconds(), "nFlows", nFlows)
		case <-tickerForTemplateFlush.C:
			slog.Info("flush ipfix template")
			buf1 := bytes.Buffer{}
			templateMessage, err := config.ToFlowTemplatesMessage()
			if err != nil {
				return err
			}
			templateMessage.Header.SysupTime = 0 // TODO
			templateMessage.Header.SysupTime = uint32(util.TimeNow())
			templateMessage.Header.SequenceNumber = 0 // TODO
			templateMessage.Header.SourceID = 0       // TODO
			if err := templateMessage.Write(&buf1); err != nil {
				return err
			}
			for _, o := range config.Outputs {
				if !o.Valid() {
					return fmt.Errorf("invalid config")
				}
				if o.Collector != nil {
					if err := util.UdpTransmit(o.Collector.LocalAddress,
						o.Collector.RemoteAddress, &buf1); err != nil {
						return err
					}
				}
			}
		}
	}
}

func flushCachesFinished(config ipfix.Config) (int, error) {
	ebpfFlows0, err := ebpfmap.Dump()
	if err != nil {
		return 0, err
	}
	ebpfFlows := []ebpfmap.Flow{}
	for _, ebpfFlow := range ebpfFlows0 {
		if ebpfFlow.Val.Finished > 0 {
			ebpfFlows = append(ebpfFlows, ebpfFlow)
		}
	}

	for _, o := range config.Outputs {
		if !o.Valid() {
			return 0, fmt.Errorf("invalid config")
		}
		if o.Log != nil {
			if err := FlowOutputLog(ebpfFlows, o.Log.File, *o.Log); err != nil {
				return 0, err
			}
		}

		if o.Collector != nil {
			flow, err := ebpfmap.ToIpfixFlowFile(ebpfFlows)
			if err != nil {
				return 0, err
			}
			flowDataMessages, err := flow.ToFlowDataMessages(&config, 0)
			if err != nil {
				return 0, err
			}
			for _, flowDataMessage := range flowDataMessages {
				flowDataMessage.Header.SysupTime = uint32(util.TimeNow())
				buf2 := bytes.Buffer{}
				if err := flowDataMessage.Write(&buf2, &config); err != nil {
					return 0, err
				}
				if err := util.UdpTransmit(o.Collector.LocalAddress,
					o.Collector.RemoteAddress, &buf2); err != nil {
					return 0, err
				}
			}
		}
	}
	return len(ebpfFlows), err
}

func flushCaches(config ipfix.Config) (int, error) {
	ebpfFlows, err := ebpfmap.Dump()
	nFlows := len(ebpfFlows)
	if err != nil {
		return 0, err
	}
	for _, o := range config.Outputs {
		if !o.Valid() {
			return 0, fmt.Errorf("invalid config")
		}
		if o.Log != nil {
			if err := FlowOutputLog(ebpfFlows, o.Log.File, *o.Log); err != nil {
				return 0, err
			}
		}

		if o.Collector != nil {
			flow, err := ebpfmap.ToIpfixFlowFile(ebpfFlows)
			if err != nil {
				return 0, err
			}
			flowDataMessages, err := flow.ToFlowDataMessages(&config, 0)
			if err != nil {
				return 0, err
			}
			for _, flowDataMessage := range flowDataMessages {
				flowDataMessage.Header.SysupTime = uint32(util.TimeNow())
				buf2 := bytes.Buffer{}
				if err := flowDataMessage.Write(&buf2, &config); err != nil {
					return 0, err
				}
				if err := util.UdpTransmit(o.Collector.LocalAddress,
					o.Collector.RemoteAddress, &buf2); err != nil {
					return 0, err
				}
			}
		}
	}
	return nFlows, nil
}

func epochMillisTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	nanos := t.UnixNano()
	millis := nanos / int64(time.Millisecond)
	enc.AppendInt64(millis)
}

func getlogger(out string) logr.Logger {
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{
		out,
	}
	cfg.EncoderConfig.EncodeTime = epochMillisTimeEncoder
	zapLog, err := cfg.Build()
	if err != nil {
		panic(fmt.Sprintf("who watches the watchmen (%v)?", err))
	}
	log := zapr.NewLogger(zapLog)
	return log

}

func ebpflowsToMapArray(flows []ebpfmap.Flow) ([]map[string]interface{}, error) {
	flowTmp := []map[string]interface{}{}
	for _, f := range flows {
		start, err := util.KtimeToRealMilli(f.Val.FlowStartMilliSecond / 1000000)
		if err != nil {
			return nil, err
		}
		end, err := util.KtimeToRealMilli(f.Val.FlowEndMilliSecond / 1000000)
		if err != nil {
			return nil, err
		}

		flowTmp = append(flowTmp, map[string]interface{}{
			"src":            util.ConvertUint32ToIP(f.Key.Saddr).String(),
			"dst":            util.ConvertUint32ToIP(f.Key.Daddr).String(),
			"proto":          f.Key.Proto,
			"sport":          f.Key.Sport,
			"dport":          f.Key.Dport,
			"ingressIfindex": f.Key.IngressIfindex,
			"egressIfindex":  f.Key.EgressIfindex,
			"pkts":           f.Val.FlowPkts,
			"bytes":          f.Val.FlowBytes,
			"action":         f.Key.Mark,
			"start":          start,
			"end":            end,
			"finished":       f.Val.Finished,
		})
	}
	return flowTmp, nil
}

func tozap(m map[string]interface{}) []interface{} {
	ret := []interface{}{}
	for key, val := range m {
		ret = append(ret, key, val)
	}
	return ret
}

func FlowOutputLog(flows []ebpfmap.Flow, out string, o ipfix.OutputLog) error {
	flowTmp, err := ebpflowsToMapArray(flows)
	if err != nil {
		return err
	}

	for _, h := range o.Hooks {
		var err error
		flowTmp, err = h.ExecuteBatch(flowTmp)
		if err != nil {
			return err
		}
	}

	log := getlogger(out)
	for _, flow := range flowTmp {
		log.Info("flowlog", tozap(flow)...)
	}
	return nil
}
