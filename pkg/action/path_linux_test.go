// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// openDescriptorCount returns how many descriptors the process has open.
func openDescriptorCount(t *testing.T) int {
	t.Helper()
	r, err := os.OpenRoot("/proc/self/fd")
	if err != nil {
		t.Fatalf("open /proc/self/fd: %v", err)
	}
	defer r.Close()
	entries, err := file.ReadDir(r)
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestWalkRootCloseReleasesDescriptors counts the process's descriptors, so
// it does not run in parallel.
func TestWalkRootCloseReleasesDescriptors(t *testing.T) {
	dir := t.TempDir()
	for i := range 8 {
		scanTestWriteFile(t, filepath.Join(dir, fmt.Sprintf("d%d", i), "sub", "f"), []byte("x"))
	}
	before := openDescriptorCount(t)
	w, files, err := walkScanPath(t.Context(), dir)
	if err != nil || len(files) != 8 {
		t.Fatalf("walkScanPath: got = (%d files, %v), want = (8, nil)", len(files), err)
	}
	for _, f := range files {
		// Leaves the roots on the files' directories open and idle.
		if _, _, release, err := w.dirs.Parent(f.name); err == nil {
			release()
		}
	}
	w.close()
	if after := openDescriptorCount(t); after > before {
		t.Errorf("open descriptors: got = %d after closing the walk root, want at most the %d before", after, before)
	}
}

// TestRunQueueReleasesDescriptors counts the process's descriptors, so it
// does not run in parallel.
func TestRunQueueReleasesDescriptors(t *testing.T) {
	yrs, rfs := scanTestRules(t)
	dir := diffTestTempDir(t)
	paths := make([]string, 0, 5)
	for i := range 4 {
		paths = append(paths, scanTestWriteFile(t, filepath.Join(dir, fmt.Sprintf("d%d", i), "locale.sh"), []byte(scanTestLocaleScript)))
	}
	nested := queueTestZip(t, queueTestEntry{name: "app/sub/locale.sh", data: []byte(scanTestLocaleScript)})
	paths = append(paths, scanTestWriteFile(t, filepath.Join(dir, "d0", "bundle.zip"), queueTestZip(t,
		queueTestEntry{name: "app/locale.sh", data: []byte(scanTestLocaleScript)},
		queueTestEntry{name: "app/lib/inner.zip", data: nested},
	)))
	c := malcontent.Config{Rules: yrs, RuleFS: rfs}
	scanInfo := scanPathInfo{originalPath: dir, effectivePath: dir}
	logger, _ := scanTestLogger()

	before := openDescriptorCount(t)
	w, _, err := openWalkRoot(dir)
	if err != nil {
		t.Fatalf("openWalkRoot: %v", err)
	}
	r := initializeReport(nil)
	if err := runQueue(t.Context(), w, walkedFiles(w, paths), 4, scanInfo, c, r, make(chan matchResult, 1), &sync.Once{}, logger); err != nil {
		t.Fatalf("runQueue: %v", err)
	}
	// A file in a subdirectory that vanished before it was scanned fails
	// the scan, and still releases its directory.
	vanished := filepath.Join(dir, "d1", "vanished.sh")
	if err := runQueue(t.Context(), w, walkedFiles(w, []string{vanished}), 1, scanInfo, c, initializeReport(nil), make(chan matchResult, 1), &sync.Once{}, logger); err == nil {
		t.Fatal("runQueue of a vanished file: got nil error, want its failure")
	}
	w.close()
	if r.Files.Size() < 6 {
		t.Fatalf("fixture precondition: reports: got = %d, want the files and the archive entries", r.Files.Size())
	}
	if after := openDescriptorCount(t); after > before {
		t.Errorf("open descriptors: got = %d after the scan, want at most the %d before", after, before)
	}
}
