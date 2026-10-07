// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

func TestFileInUnreadableDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	dir := t.TempDir()
	if err := file.MkdirAllIn(dir, "sub", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := file.WriteFileIn(dir, filepath.Join("sub", "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	// Searchable but not readable: the path resolves, but no root can be
	// opened on its directory.
	if err := root.Chmod("sub", 0o300); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = root.Chmod("sub", 0o700) })
	if ft, err := File(t.Context(), filepath.Join(dir, "sub", "run.sh")); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("File: got = (%v, %v), want = (nil, %v)", ft, err, fs.ErrPermission)
	}
}

// TestFileClosesWhatItOpens counts the process's descriptors, so it does not
// run in parallel.
func TestFileClosesWhatItOpens(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"run.sh": "#!/bin/sh\necho hi\n", "empty": ""} {
		if err := file.WriteFileIn(dir, name, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	count := func() int {
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
	before := count()
	for range 10 {
		for _, name := range []string{"run.sh", "empty", "missing"} {
			_, _ = File(t.Context(), filepath.Join(dir, name))
		}
		_, _ = File(t.Context(), dir)
	}
	if after := count(); after > before {
		t.Errorf("open descriptors: got = %d after, want at most the %d before", after, before)
	}
}
