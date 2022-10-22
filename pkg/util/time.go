package util

import (
	"syscall"
	"time"
)

func KtimeToReal(ktime uint64) (uint64, error) {
	sysinfo := &syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(sysinfo); err != nil {
		return 0, err
	}

	dt := time.Now()
	dt = dt.Add(-1 * (time.Second * time.Duration(uint64(sysinfo.Uptime))))
	return uint64(dt.UnixNano()) + ktime, nil
}

func TimeNow() uint64 {
	return uint64(time.Now().Unix())
}

func TimeNowNano() uint64 {
	return uint64(time.Now().UnixNano())
}

func KtimeToRealNano(ktime uint64) (uint64, error) {
	sysinfo := &syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(sysinfo); err != nil {
		return 0, err
	}

	dt := time.Now()
	dt = dt.Add(-1 * (time.Second * time.Duration(uint64(sysinfo.Uptime))))
	return uint64(dt.UnixNano()) + ktime, nil
}

func KtimeToRealMilli(ktimeMilli uint64) (uint64, error) {
	sysinfo := &syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(sysinfo); err != nil {
		return 0, err
	}

	dt := time.Now()
	dt = dt.Add(-1 * (time.Second * time.Duration(uint64(sysinfo.Uptime))))
	return uint64(dt.UnixMilli()) + ktimeMilli, nil
}
