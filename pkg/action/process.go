package action

import (
	"context"
	"os"

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
		return nil, err
	}

	// Store PIDs and their respective commands (paths) in a map of paths and their Process structs
	processMap := make(map[string]Process, len(procs))
	for _, p := range procs {
		path, err := p.Exe()
		if err != nil {
			return nil, err
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
	result := make([]Process, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	return result
}

// isValidPath checks if the given path is valid.
func isValidPath(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
