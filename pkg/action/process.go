package action

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/chainguard-dev/clog"
	"github.com/shirou/gopsutil/v4/process"
)

type Process struct {
	PID  int32
	Path string
}

// GetAllProcessPaths is an exported function that returns a slice of Process PIDs and commands (path).
func GetAllProcessPaths(ctx context.Context) ([]Process, error) {
	// Retrieve all of the active PIDs
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("processes: %w", err)
	}

	// Store PIDs and their respective commands (paths) in a map of paths and their Process structs
	processMap := make(map[string]Process, len(procs))
	for _, p := range procs {
		path, err := p.Exe()
		// Executable resolution is non-fatal
		if err != nil {
			name, _ := p.Name()
			clog.Errorf("%s[%d]: %v", name, p.Pid, err)
			continue
		}
		if _, exists := processMap[path]; !exists && path != "" && isValidPath(path) {
			processMap[path] = Process{
				PID:  p.Pid,
				Path: path,
			}
		}
	}

	return procMapSlice(processMap), nil
}

// procMapSlice converts a map of paths and their Process structs to a slice of Processes.
func procMapSlice(m map[string]Process) []Process {
	ps := make([]Process, 0, len(m))
	for _, v := range m {
		ps = append(ps, v)
	}

	sort.Slice(ps, func(i, j int) bool {
		return ps[i].Path < ps[j].Path
	})
	return ps
}

// isValidPath checks if the given path is valid.
func isValidPath(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
