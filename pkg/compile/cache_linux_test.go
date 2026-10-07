// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// compileOpenFilesAt counts the process's descriptors open on dir or beneath
// it.
func compileOpenFilesAt(t *testing.T, dir string) int {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, err)
	}
	return compileOpenFilesUnder(t, dir) + func() int {
		fds, err := os.OpenRoot("/proc/self/fd")
		if err != nil {
			t.Skipf("open file descriptors are not listable: %v", err)
		}
		defer func() { _ = fds.Close() }()
		entries, err := fs.ReadDir(fds.FS(), ".")
		if err != nil {
			t.Skipf("open file descriptors are not listable: %v", err)
		}
		n := 0
		for _, e := range entries {
			if target, err := fds.Readlink(e.Name()); err == nil && target == resolved {
				n++
			}
		}
		return n
	}()
}

func TestCacheFunctionsCloseTheCacheDirectory(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory.
	cache := compileIsolateCache(t)
	dir := cache.Name()
	s, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplitCached: %v", err)
	}
	// The test's own root on the cache directory stays open.
	before := compileOpenFilesAt(t, dir)
	for range 3 {
		if _, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS}); err != nil {
			t.Fatalf("RecursiveSplitCached: %v", err)
		}
		if _, err := s.CompileScoped(t.Context(), []int{0, 1}); err != nil {
			t.Fatalf("CompileScoped: %v", err)
		}
	}
	if err := cache.Chmod(".", 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	for range 3 {
		if c, err := openCacheDir(); err == nil {
			_ = c.Close()
			t.Fatal("openCacheDir with unsafe permissions: got nil error, want one")
		}
	}
	if err := cache.Chmod(".", 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if after := compileOpenFilesAt(t, dir); after != before {
		t.Errorf("descriptors open on the cache directory: got = %d, want = %d", after, before)
	}
}
