// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// liveHeapBytes returns the bytes of heap objects still reachable after a
// full collection.
func liveHeapBytes() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestWalkDirDeepChainHoldsLinearMemory walks a chain of directories whose
// path is long enough that keeping each ancestor's path, or root, alive while
// below it would take memory quadratic in the path's length: megabytes here,
// against well under the limit for anything linear in it. The path, about
// 6.4 KB, exceeds PATH_MAX on every platform, yet stays within the 8 KB that
// AppArmor checks, past which some CI hosts refuse to create it. It must not call t.Parallel, so that no
// other test allocates while it measures.
func TestWalkDirDeepChainHoldsLinearMemory(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(slices.Repeat([]string{strings.Repeat("d", 24)}, 256)...)
	if err := MkdirAllIn(dir, deep, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := WriteFileIn(dir, filepath.Join(deep, "f"), []byte("f"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()

	before := liveHeapBytes()
	var held uint64
	files := 0
	err = WalkDir(root, ".", func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files++
			now := liveHeapBytes()
			held = now - min(before, now)
		}
		return nil
	})
	if err != nil || files != 1 {
		t.Fatalf("WalkDir: got = (%d files, %v), want = (1, nil)", files, err)
	}
	limit := 16 * uint64(len(deep))
	t.Logf("heap held at the deepest file: %d bytes, limit %d", held, limit)
	if held > limit {
		t.Errorf("heap held at the deepest file: got = %d bytes, want <= %d", held, limit)
	}
}

func TestSplitLong(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("d/", MaxDirectPath)
	tests := []struct {
		name       string
		dir        string
		wantPrefix string
	}{
		{name: "absolute path splits at its last separator in the prefix", dir: "/" + long, wantPrefix: "/" + long[:MaxDirectPath-3]},
		{name: "relative path splits likewise", dir: long, wantPrefix: long[:MaxDirectPath-1]},
		{name: "absolute path with a long first element splits at the root", dir: "/" + strings.Repeat("x", MaxDirectPath) + "/y", wantPrefix: "/"},
		{name: "relative path with a long first element splits at the working directory", dir: strings.Repeat("x", MaxDirectPath) + "/y", wantPrefix: "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			prefix, rest := splitLong(tt.dir)
			if prefix != tt.wantPrefix {
				t.Errorf("prefix: got = %q, want = %q", prefix, tt.wantPrefix)
			}
			if len(prefix) > MaxDirectPath {
				t.Errorf("prefix: got %d bytes, want <= %d", len(prefix), MaxDirectPath)
			}
			if joined := filepath.Join(prefix, rest); joined != filepath.Clean(tt.dir) {
				t.Errorf("Join(prefix, rest): got = %q, want = %q", joined, filepath.Clean(tt.dir))
			}
		})
	}
}

// TestPathHelpersBeyondPathMax reaches a file at a path longer than PATH_MAX
// on every platform, which the operating system refuses whole.
func TestPathHelpersBeyondPathMax(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	deep := filepath.Join(slices.Repeat([]string{strings.Repeat("d", 100)}, 42)...)
	if err := MkdirAllIn(dir, deep, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := WriteFileIn(dir, filepath.Join(deep, "f"), []byte("f"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	full := filepath.Join(dir, deep)

	r, err := OpenRoot(full)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer r.Close()
	if got, err := r.ReadFile("f"); err != nil || string(got) != "f" {
		t.Errorf("read through OpenRoot: got = (%q, %v), want = (%q, nil)", got, err, "f")
	}
	if fi, err := Stat(filepath.Join(full, "f")); err != nil || fi.Size() != 1 {
		t.Errorf("Stat: got = (%v, %v), want a 1-byte file", fi, err)
	}
	f, err := Open(filepath.Join(full, "f"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = f.Close()
	if err := MkdirAll(filepath.Join(full, "new", "sub"), 0o700); err != nil {
		t.Errorf("MkdirAll: %v", err)
	}
	if _, err := OpenRoot(filepath.Join(full, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenRoot of a missing directory: got err = %v, want %v", err, fs.ErrNotExist)
	}
}
