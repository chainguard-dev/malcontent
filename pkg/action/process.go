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

// GetAllProcessPaths is an exported function that returns a slice of Process PIDs and commands (path)
func GetAllProcessPaths(ctx context.Context) ([]Process, error) {
	// Retrieve all of the active PIDs
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	// Store PIDs and their respective commands (paths) in a slice of Processes
	processPaths := []Process{}
	for _, p := range procs {
		path, err := p.Exe()
		if err != nil {
			return nil, err
		}
		if isValidPath(path) {
			processPaths = append(processPaths, Process{
				PID:  p.Pid,
				Path: path,
			})
		}
	}

	return processPaths, nil
}

// isValidPath checks if the given path is valid.
func isValidPath(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
