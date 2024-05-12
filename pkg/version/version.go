package version

import (
	"fmt"
	"os"
	"runtime/debug"
)

const (
	versionFile = "VERSION"
)

// Load the static version file.
func loadVersionFile() (*os.File, error) {
	f, err := os.Open(versionFile)
	if err != nil {
		return nil, err
	}
	return f, nil
}

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
		return "bincapz unknown version", err
	}
	// If present, return that value
	// Otherwise, fall back to the contents of the VERSION file
	if v != "" {
		return fmt.Sprintf("bincapz %s", v), nil
	}
	f, err := loadVersionFile()
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, 32)
	n, err := f.Read(buf)
	if err != nil {
		return "bincapz unknown version", err
	}
	v = string(buf[:n])
	return fmt.Sprintf("bincapz %s", v), nil
}
