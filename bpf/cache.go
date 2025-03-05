package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"os"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
// nolint
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -tags linux bpf $REPO_ROOT/bpf/cache.c

// FDMonitoringNotify register a callback function to monitor file descriptor changes.
type FDMonitoringNotify func(func(fd int, isAdd bool))

type Statistic struct {
	MinorFaultCount uint64
	MajorFaultCount uint64
	MarkAccessCount uint64
}

func (s *Statistic) CalcHitRate() float64 {
	return float64(s.MinorFaultCount+s.MajorFaultCount) / float64(s.MinorFaultCount+s.MajorFaultCount+s.MarkAccessCount)
}

func Run(fdMonitor FDMonitoringNotify) (func() Statistic, error) {
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}
	rewrite := make(map[string]interface{})
	rewrite["monitor_pid"] = uint32(os.Getpid())
	spec.RewriteConstants(rewrite)
	err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{})
	if err != nil {
		return nil, err
	}

	fdMonitor(func(fd int, isAdd bool) {
		key := uint32(fd)
		val := uint32(1)
		var monitorErr error
		if isAdd {
			monitorErr = objs.bpfMaps.MonitorFd.Put(&key, &val)
		} else {
			monitorErr = objs.bpfMaps.MonitorFd.Delete(&key)
		}
		if monitorErr != nil {
			log.Println("Error monitoring fd changes:", monitorErr)
		}
	})
	_, err = link.Kprobe("handle_mm_fault", objs.HandleMmFault, nil)
	if err != nil {
		return nil, err
	}
	_, err = link.Kprobe("mark_page_accessed", objs.MarkPageAccessed, nil)
	if err != nil {
		return nil, err
	}
	_, err = link.Tracepoint("syscalls", "sys_enter_read", objs.TracepointEnterRead, nil)
	if err != nil {
		return nil, err
	}
	_, err = link.Tracepoint("syscalls", "sys_exit_read", objs.TracepointExitRead, nil)
	if err != nil {
		return nil, err
	}
	return func() Statistic {
		result := Statistic{}
		var key uint32 = 0
		if readErr := objs.bpfMaps.GlobalStatsMap.Lookup(&key, &result); readErr != nil {
			log.Println("Error reading map:", readErr)
		}
		return result
	}, nil
}
