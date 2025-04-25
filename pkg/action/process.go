package action

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/shirou/gopsutil/v4/process"
)

type ProcessInfo struct {
	PID            int32
	PPID           int32
	Name           string
	ScanPath       string
	AdvertisedPath string
	CmdLine        []string
}

// ActiveProcesses is an exported function that a list of active processes.
func ActiveProcesses(ctx context.Context) ([]*ProcessInfo, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Retrieve all of the active PIDs
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("processes: %w", err)
	}

	found := map[string]*ProcessInfo{}
	for _, p := range procs {
		pi, err := processInfo(ctx, p)
		if err != nil {
			clog.Warnf("skipping pid %d: %v", p.Pid, err)
			continue
		}
		if pi == nil {
			continue
		}

		found[pi.ScanPath] = pi
	}

	ps := make([]*ProcessInfo, 0, len(found))
	for _, v := range found {
		ps = append(ps, v)
	}

	sort.Slice(ps, func(i, j int) bool {
		return ps[i].ScanPath < ps[j].ScanPath
	})

	return ps, nil
}

// canStat checks if stat() works on a given path.
func canStat(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// processInfo returns information about a process tuned for scanning.
func processInfo(ctx context.Context, p *process.Process) (*ProcessInfo, error) {
	pi := &ProcessInfo{
		PID: p.Pid,
	}
	name, err := p.Name()
	if err != nil {
		name = "<unknown>"
	}
	pi.Name = name

	parent, err := p.PpidWithContext(ctx)
	if err != nil {
		parent = -1
	}

	// Skip Linux kernel threads that have no backing executable
	if runtime.GOOS == "linux" && (p.Pid == 2 || parent == 2) {
		return nil, nil
	}
	pi.PPID = parent

	cmd, err := p.CmdlineSliceWithContext(ctx)
	if err == nil {
		pi.CmdLine = cmd
		if len(cmd) > 0 && strings.HasPrefix(cmd[0], "/") {
			pi.AdvertisedPath = cmd[0]
		}
	}

	// on Linux, this is effectively readlink(/proc/X/exe), but it isn't fully resolved either
	path, err := p.Exe()
	if err == nil {
		pi.ScanPath = path
		if canStat(pi.ScanPath) {
			return pi, nil
		}
	}

	// fallback if p.Exe fails to be stattable
	if runtime.GOOS == "linux" {
		pi.ScanPath = fmt.Sprintf("/proc/%d/exe", p.Pid)

		if canStat(pi.ScanPath) {
			return pi, nil
		}
	}

	// Settle for whatever binary we may have found in the process table
	if canStat(pi.AdvertisedPath) {
		pi.ScanPath = pi.AdvertisedPath
		return pi, nil
	}

	if pi.AdvertisedPath != "" {
		return nil, fmt.Errorf("%s[%d]: unable to stat %q or %q", pi.Name, pi.PID, pi.ScanPath, pi.AdvertisedPath)
	}

	return nil, fmt.Errorf("%s: unable to stat %q", pi.Name, pi.ScanPath)
}
