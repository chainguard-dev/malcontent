// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

// deepPathTestBytes returns the bytes of heap objects still reachable after a
// full collection.
func deepPathTestBytes() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestWalkScanPathDeepChainHoldsLinearMemory walks a scan path holding a chain
// of directories whose path is long enough that keeping each ancestor's paths,
// or root, alive while below it would take memory quadratic in the path's
// length. The path, about 6.4 KB, exceeds PATH_MAX yet stays within the 8 KB
// that AppArmor checks, past which some CI hosts refuse to create it. It must not call t.Parallel, so that no other test allocates while
// it measures, and it sets walkFileHook.
func TestWalkScanPathDeepChainHoldsLinearMemory(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(slices.Repeat([]string{strings.Repeat("d", 24)}, 256)...)
	if err := file.MkdirAllIn(dir, deep, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := file.WriteFileIn(dir, filepath.Join(deep, "f"), []byte("f"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	before := deepPathTestBytes()
	var held uint64
	walkFileHook = func() {
		now := deepPathTestBytes()
		held = now - min(before, now)
	}
	t.Cleanup(func() { walkFileHook = nil })

	w, files, err := walkScanPath(t.Context(), dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("walkScanPath: got = (%d files, %v), want = (1, nil)", len(files), err)
	}
	w.close()
	limit := 16 * uint64(len(deep))
	t.Logf("heap held at the deepest file: %d bytes, limit %d", held, limit)
	if held > limit {
		t.Errorf("heap held at the deepest file: got = %d bytes, want <= %d", held, limit)
	}
}

// TestScanNestedArchiveBeyondPathMax scans an archive holding another archive
// at a path longer than PATH_MAX on any platform, which no path handed to the
// operating system whole can reach. The nested archive must be extracted and
// its files scanned like any other.
func TestScanNestedArchiveBeyondPathMax(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	dir := t.TempDir()
	inner := filepath.Join(dir, "inner.zip")
	buildZipFile(t, inner, scanTestEntries(t))
	// 42 levels of 100-byte names: 4,242 bytes, past PATH_MAX everywhere.
	deep := strings.Repeat(strings.Repeat("d", 100)+"/", 42)
	outer := filepath.Join(dir, "outer.zip")
	buildZipFile(t, outer, map[string][]byte{deep + "inner.zip": readTestFile(t, inner)})

	c := malcontent.Config{Concurrency: 2, Rules: yrs, RuleFS: rfs, ScanPaths: []string{outer}}
	r, err := Scan(t.Context(), c)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := report.DisplayPath(outer, nil) + " ∴ /" + deep + "inner/app/package.json"
	if keys := scanTestKeys(r.Files); !slices.Contains(keys, want) {
		for i, k := range keys {
			keys[i] = strings.ReplaceAll(k, deep, "<deep>/")
		}
		t.Errorf("report keys: got = %q, want one = %q", keys, strings.ReplaceAll(want, deep, "<deep>/"))
	}
}

// TestScanArchiveBeyondPathMax scans a directory holding an archive at a path
// longer than PATH_MAX on any platform. The archive must be extracted and its
// files scanned like any other.
func TestScanArchiveBeyondPathMax(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	dir := t.TempDir()
	deep := strings.Repeat(strings.Repeat("d", 100)+"/", 42)
	if err := file.MkdirAllIn(dir, deep, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	staging := filepath.Join(t.TempDir(), "inner.zip")
	buildZipFile(t, staging, scanTestEntries(t))
	if err := file.WriteFileIn(dir, deep+"inner.zip", readTestFile(t, staging), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := malcontent.Config{Concurrency: 2, Rules: yrs, RuleFS: rfs, ScanPaths: []string{dir}}
	r, err := Scan(t.Context(), c)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := report.DisplayPath(filepath.Join(dir, deep+"inner.zip"), nil) + " ∴ /app/package.json"
	if keys := scanTestKeys(r.Files); !slices.Contains(keys, want) {
		for i, k := range keys {
			keys[i] = strings.ReplaceAll(k, deep, "<deep>/")
		}
		t.Errorf("report keys: got = %q, want one = %q", keys, strings.ReplaceAll(want, deep, "<deep>/"))
	}
}
