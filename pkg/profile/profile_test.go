// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"os"
	"strings"
	"testing"
)

func TestProfile(t *testing.T) {
	// Not parallel: the CPU profiler and the execution tracer are
	// process-wide, and the default output directory is relative to a
	// temporary working directory.
	t.Chdir(t.TempDir())
	p, err := StartProfiling(t.Context(), DefaultConfig())
	if err != nil {
		t.Fatalf("failed to start profiling: %v", err)
	}
	defer p.Stop()

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
