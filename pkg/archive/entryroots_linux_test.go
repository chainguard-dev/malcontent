// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
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

// TestExtractZipReleasesDescriptors counts the process's descriptors, so it
// does not run in parallel.
func TestExtractZipReleasesDescriptors(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := range 40 {
		w, err := zw.Create(fmt.Sprintf("mod/pkg%d/sub/file%d.go", i%8, i))
		if err != nil {
			t.Fatalf("create entry: %v", err)
		}
		if _, err := w.Write([]byte("package x\n")); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	dir := t.TempDir()
	if err := file.WriteFileIn(dir, "a.zip", buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write zip: %v", err)
	}

	before := openDescriptorCount(t)
	if err := ExtractZip(t.Context(), filepath.Join(dir, "out"), filepath.Join(dir, "a.zip")); err != nil {
		t.Fatalf("ExtractZip: %v", err)
	}
	if after := openDescriptorCount(t); after > before {
		t.Errorf("open descriptors: got = %d after extracting, want at most the %d before", after, before)
	}
}
