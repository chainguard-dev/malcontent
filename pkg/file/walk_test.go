// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// walkTestTree returns a root on a temporary directory holding names, each
// file containing its own name.
func walkTestTree(t *testing.T, names ...string) *os.Root {
	t.Helper()
	dir := rootTestDir(t)
	for _, name := range names {
		if err := MkdirAllIn(dir, filepath.Dir(name), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := WriteFileIn(dir, name, []byte(name), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// walkTestPaths returns the paths w yields, detaching the directories that
// detach names and skipping those that skip names.
func walkTestPaths(t *testing.T, w *Walker, detach, skip string) []string {
	t.Helper()
	defer w.Close()
	var got []string
	for w.Next() {
		got = append(got, w.Path())
		switch w.Path() {
		case detach:
			dir, err := w.Detach()
			if err != nil {
				t.Fatalf("Detach(%q): %v", w.Path(), err)
			}
			_ = dir.Close()
		case skip:
			w.SkipDir()
		}
	}
	return got
}

func TestWalker(t *testing.T) {
	t.Parallel()
	r := walkTestTree(t, "a/x.txt", "a/b/y.txt", "c/z.txt", "c/zz.txt", "top.txt")
	tests := []struct {
		name   string
		start  string
		detach string
		skip   string
		want   []string
	}{
		{name: "whole tree", start: ".", want: []string{".", "a", "a/b", "a/b/y.txt", "a/x.txt", "c", "c/z.txt", "c/zz.txt", "top.txt"}},
		{name: "detached directory is not walked", start: ".", detach: "a", want: []string{".", "a", "c", "c/z.txt", "c/zz.txt", "top.txt"}},
		{name: "detached directory without later siblings is not walked", start: ".", detach: "a/b", want: []string{".", "a", "a/b", "a/x.txt", "c", "c/z.txt", "c/zz.txt", "top.txt"}},
		{name: "skipped directory is not walked", start: "a", skip: "a/b", want: []string{"a", "a/b", "a/x.txt"}},
		{name: "skipped file skips the rest of its directory", start: ".", skip: "c/z.txt", want: []string{".", "a", "a/b", "a/b/y.txt", "a/x.txt", "c", "c/z.txt", "top.txt"}},
		{name: "skipped last file skips nothing more", start: ".", skip: "a/b/y.txt", want: []string{".", "a", "a/b", "a/b/y.txt", "a/x.txt", "c", "c/z.txt", "c/zz.txt", "top.txt"}},
		{name: "subtree", start: "a/b", want: []string{"a/b", "a/b/y.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := walkTestPaths(t, NewWalker(r, tt.start), tt.detach, tt.skip); !slices.Equal(got, tt.want) {
				t.Errorf("paths:\ngot  = %q\nwant = %q", got, tt.want)
			}
		})
	}
}

func TestNewDirWalker(t *testing.T) {
	t.Parallel()
	r := walkTestTree(t, "a/x.txt", "a/b/y.txt", "c/z.txt")
	tests := []struct {
		name string
		dir  string
		want []string
	}{
		{name: "entries beneath the directory, without it", dir: "a", want: []string{"a/b", "a/b/y.txt", "a/x.txt"}},
		{name: "entries of the walk root have bare names", dir: ".", want: []string{"a", "a/b", "a/b/y.txt", "a/x.txt", "c", "c/z.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, err := r.OpenRoot(tt.dir)
			if err != nil {
				t.Fatalf("OpenRoot: %v", err)
			}
			info, err := r.Stat(tt.dir)
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			if got := walkTestPaths(t, NewDirWalker(dir, tt.dir, fs.FileInfoToDirEntry(info)), "", ""); !slices.Equal(got, tt.want) {
				t.Errorf("paths:\ngot  = %q\nwant = %q", got, tt.want)
			}
		})
	}
}

func TestWalkerDetachRefusesAFile(t *testing.T) {
	t.Parallel()
	r := walkTestTree(t, "top.txt")
	w := NewWalker(r, "top.txt")
	defer w.Close()
	if !w.Next() {
		t.Fatal("Next: got = false, want the start entry")
	}
	if dir, err := w.Detach(); dir != nil || !errors.Is(err, errNotWalkable) {
		t.Errorf("Detach: got = (%v, %v), want = (nil, %v)", dir, err, errNotWalkable)
	}
}

// walkTestOpenFiles returns how many descriptors the process has open, or
// skips the test where they cannot be listed.
func walkTestOpenFiles(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("list open descriptors: %v", err)
	}
	return len(entries)
}

// TestWalkerCloseReleasesRoots stops walks partway and checks that Close
// releases every root they hold. It must not call t.Parallel, since it counts
// the process's descriptors.
func TestWalkerCloseReleasesRoots(t *testing.T) {
	r := walkTestTree(t, "a/b/c/d/x.txt", "a/b/c/y.txt", "a/b/z.txt", "a/w.txt", "e/f.txt")
	for _, stopAt := range []string{".", "a", "a/b/c", "a/b/c/d/x.txt", "a/b/c/y.txt", "e/f.txt"} {
		t.Run(stopAt, func(t *testing.T) {
			before := walkTestOpenFiles(t)
			w := NewWalker(r, ".")
			for w.Next() && w.Path() != stopAt {
			}
			w.Close()
			if after := walkTestOpenFiles(t); after != before {
				t.Errorf("open descriptors after Close: got = %d, want = %d", after, before)
			}
		})
	}
}
