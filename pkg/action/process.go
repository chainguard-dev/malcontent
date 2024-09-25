package action

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type Process struct {
	PID  int
	Path string
}

// GetAllProcessPaths is an exported function that retrieves the process commands.
func GetAllProcessPaths() ([]Process, error) {
	switch runtime.GOOS {
	case "linux", "darwin":
		return getUnixProcessPaths()
	case "windows":
		return getWindowsProcessPaths()
	default:
		return nil, fmt.Errorf("unsupported operating system")
	}
}

// getUnixProcessPaths is a UNIX-focused function to retrieve PIDs and their respective commands.
func getUnixProcessPaths() ([]Process, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("ps", "-e", "-o", "pid=,comm=")
	case "linux":
		cmd = exec.Command("ps", "-e", "-o", "pid=,cmd=")
	}
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	pidMap := make(map[string]Process)
	lines := strings.Split(string(output), "\n")
	// Iterate through the output lines
	for _, line := range lines {
		fields := strings.Fields(line)

		// If a PID and command were returned, parse them and store them in the map
		if len(fields) >= 2 {
			pid, err := strconv.Atoi(fields[0])
			if err != nil {
				return nil, err
			}
			path := strings.TrimSpace(strings.Join(fields[1:], " "))
			if _, exists := pidMap[path]; !exists && path != "" && isValidPath(path) {
				pidMap[path] = Process{PID: pid, Path: path}
			}
		}
	}

	return mapToSlice(pidMap), nil
}

// getWindowsProcessPaths is a Windows-focused function to retrieve PIDs and their respective commands.
func getWindowsProcessPaths() ([]Process, error) {
	cmd := exec.Command("wmic", "process", "get", "ProcessId,ExecutablePath")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	pidMap := make(map[string]Process)
	lines := strings.Split(string(output), "\n")
	// Iterate through the output lines
	// Ignore the header
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pid, err := strconv.Atoi(fields[len(fields)-1])
			if err != nil {
				return nil, err
			}
			path := strings.TrimSpace(strings.Join(fields[:len(fields)-1], " "))
			if _, exists := pidMap[path]; !exists && path != "" && isValidPath(path) {
				pidMap[path] = Process{PID: pid, Path: path}
			}
		}
	}

	return mapToSlice(pidMap), nil
}

// mapToSlice converts a map of paths and their Process structs to a slice of Processes.
func mapToSlice(m map[string]Process) []Process {
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
