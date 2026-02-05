// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// countOpenFDs returns the number of open file descriptors for the current process.
// Returns -1 if unable to count (e.g., on unsupported platforms).
func countOpenFDs(t *testing.T) int {
	t.Helper()

	// Linux: count entries in /proc/self/fd
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		return len(entries)
	}

	// macOS: count entries in /dev/fd
	if entries, err := os.ReadDir("/dev/fd"); err == nil {
		return len(entries)
	}

	return -1
}

// TestScanSinglePathNoFDLeak verifies that early return paths in scanSinglePath
// properly close file handles and don't leak file descriptors.
func TestScanSinglePathNoFDLeak(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fdsBefore := countOpenFDs(t)
	if fdsBefore == -1 {
		t.Skip("cannot count file descriptors on this platform")
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	cfg := malcontent.Config{
		Concurrency:      runtime.NumCPU(),
		IgnoreSelf:       false,
		IncludeDataFiles: false,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            yrs,
		RuleFS:           rfs,
	}

	testFiles := []string{
		filepath.Join("testdata", "empty"),
		filepath.Join("testdata", "rando"),
		filepath.Join("testdata", "short"),
	}

	iterations := runtime.GOMAXPROCS(0) * 10
	for range iterations {
		for _, tf := range testFiles {
			_, _ = scanSinglePath(ctx, cfg, tf, rfs, tf, "", nil)
		}
	}

	runtime.GC()

	fdsAfter := countOpenFDs(t)

	maxAllowedGrowth := 0
	leaked := fdsAfter - fdsBefore
	if leaked > maxAllowedGrowth {
		t.Errorf("file descriptor leak detected: before=%d after=%d leaked=%d (ran %d iterations)",
			fdsBefore, fdsAfter, leaked, iterations*len(testFiles))
	}
}

// TestScanSinglePathNonExistentFile verifies that scanning a non-existent file
// returns an error without leaking resources.
func TestScanSinglePathNonExistentFile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fdsBefore := countOpenFDs(t)
	if fdsBefore == -1 {
		t.Skip("cannot count file descriptors on this platform")
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	cfg := malcontent.Config{
		Rules:  yrs,
		RuleFS: rfs,
	}

	iterations := runtime.GOMAXPROCS(0) * 10
	for range iterations {
		_, err := scanSinglePath(ctx, cfg, "/nonexistent/path/to/file", rfs, "", "", nil)
		if err == nil {
			t.Error("expected error for non-existent file")
		}
	}

	runtime.GC()

	fdsAfter := countOpenFDs(t)
	maxAllowedGrowth := 0
	leaked := fdsAfter - fdsBefore
	if leaked > maxAllowedGrowth {
		t.Errorf("file descriptor leak on error path: before=%d after=%d leaked=%d",
			fdsBefore, fdsAfter, leaked)
	}
}

// TestScanRepeatedScansNoResourceExhaustion verifies that repeated scans
// don't exhaust scanner pool or buffer pool resources.
func TestScanRepeatedScansNoResourceExhaustion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	cfg := malcontent.Config{
		Concurrency:      runtime.NumCPU(),
		IgnoreSelf:       false,
		IncludeDataFiles: false,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            yrs,
		RuleFS:           rfs,
	}

	testFiles := []string{
		filepath.Join("testdata", "empty"), // zero-sized, early return before scanner
		filepath.Join("testdata", "rando"), // data file, early return before scanner
		filepath.Join("testdata", "shell"), // actual script, full scan path
	}

	iterations := runtime.GOMAXPROCS(0) * 10

	for range iterations {
		for _, tf := range testFiles {
			_, _ = scanSinglePath(ctx, cfg, tf, rfs, tf, "", nil)
		}
	}
}
