// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// descriptorTableSize returns how many descriptors the process's table holds,
// as /proc/self/status reports it.
func descriptorTableSize(t *testing.T) int64 {
	t.Helper()
	status, err := ReadFileIn("/proc/self", "status")
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	for line := range bytes.Lines(status) {
		if v, ok := bytes.CutPrefix(line, []byte("FDSize:")); ok {
			n, err := strconv.ParseInt(string(bytes.TrimSpace(v)), 10, 64)
			if err != nil {
				t.Fatalf("parse FDSize %q: %v", v, err)
			}
			return n
		}
	}
	t.Fatal("status has no FDSize")
	return 0
}

// openDescriptors returns the descriptors the process has open.
func openDescriptors(t *testing.T) []int64 {
	t.Helper()
	r, err := os.OpenRoot("/proc/self/fd")
	if err != nil {
		t.Fatalf("open /proc/self/fd: %v", err)
	}
	defer r.Close()
	entries, err := ReadDir(r)
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	fds := make([]int64, 0, len(entries))
	for _, e := range entries {
		if fd, err := strconv.ParseInt(e.Name(), 10, 64); err == nil {
			fds = append(fds, fd)
		}
	}
	return fds
}

// TestGrowDescriptorTable lists the process's descriptors, so it does not run
// in parallel: TestReserveDescriptorsHoldsTwiceTheIdleRootBudget briefly holds
// a copy above the table size this test starts from.
func TestGrowDescriptorTable(t *testing.T) {
	want := 4 * descriptorTableSize(t)
	if want > openFileLimit() {
		t.Skipf("growing the table to %d descriptors exceeds the limit of %d", want, openFileLimit())
	}
	growDescriptorTable(want)
	if got := descriptorTableSize(t); got < want {
		t.Errorf("descriptor table size: got = %d, want at least %d", got, want)
	}
	for _, fd := range openDescriptors(t) {
		if fd >= want-1 {
			t.Errorf("descriptor %d: got it open, want the copy that grew the table closed", fd)
		}
	}
}

func TestReserveDescriptorsHoldsTwiceTheIdleRootBudget(t *testing.T) {
	t.Parallel()
	growTableForIdleRoots()
	if got, want := descriptorTableSize(t), 2*idleRootBudget(); got < want {
		t.Errorf("descriptor table size: got = %d, want at least %d", got, want)
	}
}

// TestHelpersCloseTheirRoots counts the process's descriptors, so it does not
// run in parallel.
func TestHelpersCloseTheirRoots(t *testing.T) {
	dir := rootTestDir(t)
	if err := WriteFileIn(dir, "file", []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFileIn: %v", err)
	}
	rootTestSymlink(t, dir, "file", "link")
	path, link := filepath.Join(dir, "file"), filepath.Join(dir, "link")
	before := len(openDescriptors(t))
	for i := range 20 {
		_, _ = Stat(path)
		_, _ = ReadFile(link)
		_, _ = StatIn(dir, "file")
		_, _ = LstatIn(dir, "link")
		_, _ = ReadFileIn(dir, "file")
		if f, err := Open(path); err == nil {
			_ = f.Close()
		}
		if f, err := OpenIn(dir, "file"); err == nil {
			_ = f.Close()
		}
		_ = MkdirAll(filepath.Join(dir, "made", strconv.Itoa(i)), 0o700)
		_ = MkdirAllIn(dir, "madein", 0o700)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	d := NewDirRoots(root, 4)
	for i := range 20 {
		// Each directory is opened through its parent's root, which is
		// released again.
		if r, _, release, err := d.Parent(filepath.Join("made", strconv.Itoa(i), "x")); err == nil {
			_, _ = r.Stat(".")
			release()
		}
	}
	d.Close()
	_ = root.Close()
	if after := len(openDescriptors(t)); after > before {
		t.Errorf("open descriptors: got = %d after, want at most the %d before", after, before)
	}
}
