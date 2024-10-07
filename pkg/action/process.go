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

type Process struct {
	PID  int32
	Path string
}

// ActiveProcessPaths is an exported function that returns a slice of Process PIDs and commands (path).
func ActiveProcessPaths(ctx context.Context) ([]Process, error) {
	// Retrieve all of the active PIDs
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("processes: %w", err)
	}

	found := map[string]Process{}
	for _, p := range procs {
		// Skip Linux kernel threads
		if runtime.GOOS == "linux" {
			if p.Pid == 2 {
				continue
			}
			parent, _ := p.PpidWithContext(ctx)
			if parent == 2 {
				continue
			}
		}

		path, err := processPath(ctx, p)
		if err != nil {
			clog.Warnf("skipping pid %d: %v", p.Pid, err)
			continue
		}

		// NOTE: this only stores the last pid we found for a process, we may want to adjust that
		found[path] = Process{
			PID:  p.Pid,
			Path: path,
		}
	}

	ps := make([]Process, 0, len(found))
	for _, v := range found {
		ps = append(ps, v)
	}

	sort.Slice(ps, func(i, j int) bool {
		return ps[i].Path < ps[j].Path
	})

	return ps, nil
}

// canStat checks if stat() works on a given path
func canStat(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// processPath returns the best path to a process executable
func processPath(ctx context.Context, p *process.Process) (string, error) {
	// on Linux, this is effectively readlink(/proc/X/exe)
	path, eErr := p.Exe()
	if eErr == nil {
		if canStat(path) {
			return path, nil
		}
		// maybe the path was deleted? fallback to the original executable
		if runtime.GOOS == "linux" {
			path := fmt.Sprintf("/proc/%d/exe", p.Pid)
			if canStat(path) {
				return path, nil
			}
		}
	}

	// on Linux, p.Exe() isn't available for other users processes unless you are root, try an alternate route.
	cmd, err := p.CmdlineSliceWithContext(ctx)
	if err == nil {
		if len(cmd) > 0 && strings.HasPrefix(cmd[0], "/") {
			if canStat(cmd[0]) {
				return cmd[0], nil
			}
			return "", fmt.Errorf("%q is inacessible", cmd[0])
		}
	}

	name, err := p.Name()
	if err != nil {
		name = "<unknown>"
	}
	return "", fmt.Errorf("%q: %w", name, eErr)
}
