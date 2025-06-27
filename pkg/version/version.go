package version

import (
	"fmt"
	"runtime/debug"
)

const (
	ID string = "v1.13.1"
)

// Check if the build info contains a version.
func getBinaryVersion() (string, error) {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return "", fmt.Errorf("failed to read build info")
	}

	for _, setting := range buildInfo.Settings {
		if setting.Key == "main.BuildVersion" {
			return setting.Value, nil
		}
	}

	return "", nil
}

func Version() (string, error) {
	var v string
	var err error
	// Check for the version in the binary first
	if v, err = getBinaryVersion(); err != nil {
		return "malcontent unknown version", err
	}
	// If present, return that value
	// Otherwise, fall back to the contents of the VERSION const
	if v != "" {
		return v, nil
	}
	return ID, nil
}
