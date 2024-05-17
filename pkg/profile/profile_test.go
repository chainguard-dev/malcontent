package profile

import (
	"os"
	"strings"
	"testing"
)

func TestProfile(t *testing.T) {
	stop, err := Profile()
	if err != nil {
		t.Fatalf("failed to start profiling: %v", err)
	}
	defer func() {
		stop()
		os.RemoveAll("profiles")
	}()

	files, err := os.ReadDir("profiles")
	if err != nil {
		t.Fatalf("failed to read profiles directory: %v", err)
	}

	expectedFiles := []string{"cpu_", "mem_", "trace_"}
	for _, expected := range expectedFiles {
		found := false
		for _, file := range files {
			if strings.HasPrefix(file.Name(), expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("did not find file starting with %s", expected)
		}
	}
}
