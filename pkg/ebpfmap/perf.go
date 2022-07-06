package ebpfmap

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

type PerfObject struct {
	MapID ebpf.MapID
	rec   perf.Record
}

func (po PerfObject) Ifindex() uint32 {
	padding := make([]byte, 4-len(po.rec.RawSample))
	i := binary.LittleEndian.Uint32(append(padding, po.rec.RawSample...))
	return i
}

func StartReaderPerMap(mapID ebpf.MapID, poCh chan PerfObject) error {
	m, err := ebpf.NewMapFromID(mapID)
	if err != nil {
		return err
	}
	defer m.Close()

	rd, err := perf.NewReader(m, 4096)
	if err != nil {
		return err
	}
	defer rd.Close()

	for {
		rec, err := rd.Read()
		if err != nil {
			return err
		}
		po := PerfObject{
			MapID: mapID,
			rec:   rec,
		}
		poCh <- po
	}
}

func StartReader() (chan PerfObject, error) {
	ids, err := GetMapIDsByNameType("events", ebpf.PerfEventArray)
	if err != nil {
		return nil, err
	}

	poCh := make(chan PerfObject, 10)
	for _, id := range ids {
		go func(id ebpf.MapID) {
			for {
				if err := StartReaderPerMap(id, poCh); err != nil {
					fmt.Printf("FAIL: %s ... ignored", err.Error())
				}
			}
		}(id)
	}

	return poCh, nil
}
