package profile

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestProfile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, err := StartProfiling(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("failed to start profiling: %v", err)
	}
	defer func() {
		p.Stop()
		os.RemoveAll("profiles")
	}()

	files, err := os.ReadDir("profiles")
	if err != nil {
		t.Fatalf("failed to read profiles directory: %v", err)
	}

	found := false
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "profile_") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("did not find file starting with profile_")
	}
}
