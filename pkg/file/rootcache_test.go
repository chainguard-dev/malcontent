// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// rootCacheTestTree returns a root on a temporary directory holding d/N/f.txt
// for N below dirs, and a RootCache opening directories beneath it, keeping
// maxIdle idle roots, with a count of the roots it opened.
func rootCacheTestTree(t *testing.T, dirs, maxIdle int) (*RootCache, *atomic.Int64) {
	t.Helper()
	dir := t.TempDir()
	for i := range dirs {
		name := filepath.Join("d", fmt.Sprint(i), "f.txt")
		if err := MkdirAllIn(dir, filepath.Dir(name), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := WriteFileIn(dir, name, []byte(fmt.Sprint(i)), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	var opened atomic.Int64
	// One shard keeps the least recently used order exact across all roots.
	c := newShardedRootCache(func(dir string) (*os.Root, error) {
		opened.Add(1)
		return root.OpenRoot(dir)
	}, maxIdle, 1)
	t.Cleanup(func() {
		c.Close()
		_ = root.Close()
	})
	return c, &opened
}

func rootCacheTestDir(i int) string { return filepath.Join("d", fmt.Sprint(i)) }

func TestRootCacheGet(t *testing.T) {
	t.Parallel()
	c, opened := rootCacheTestTree(t, 1, 4)

	r1, release1, err := c.Get(rootCacheTestDir(0))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, err := r1.ReadFile("f.txt"); err != nil || string(got) != "0" {
		t.Errorf("read through the root: got = (%q, %v), want = (%q, nil)", got, err, "0")
	}
	r2, release2, err := c.Get(rootCacheTestDir(0))
	if err != nil || r2 != r1 {
		t.Errorf("second Get: got = (%p, %v), want the same root %p", r2, err, r1)
	}
	release1()
	release2()
	r3, release3, err := c.Get(rootCacheTestDir(0))
	if err != nil || r3 != r1 {
		t.Errorf("Get after release: got = (%p, %v), want the idle root %p reused", r3, err, r1)
	}
	release3()
	if got := opened.Load(); got != 1 {
		t.Errorf("roots opened: got = %d, want = 1", got)
	}
	if _, _, err := c.Get("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Get of a missing directory: got err = %v, want = %v", err, fs.ErrNotExist)
	}
}

func TestRootCacheClosesIdleRootsBeyondTheBound(t *testing.T) {
	t.Parallel()
	const maxIdle = 3
	c, _ := rootCacheTestTree(t, maxIdle+3, maxIdle)
	first, releaseFirst, err := c.Get(rootCacheTestDir(0))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// A root in use is never closed, however many others go idle.
	held, releaseHeld, err := c.Get(rootCacheTestDir(1))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	releaseFirst()
	for i := 2; i < maxIdle+3; i++ {
		_, release, err := c.Get(rootCacheTestDir(i))
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		release()
	}
	if got := c.shards[0].idle.Len(); got != maxIdle {
		t.Errorf("idle roots: got = %d, want = %d", got, maxIdle)
	}
	if _, err := first.Stat("f.txt"); err == nil {
		t.Error("least recently used idle root: got it open, want it closed")
	}
	if _, err := held.Stat("f.txt"); err != nil {
		t.Errorf("root in use: got err = %v, want it open", err)
	}
	releaseHeld()
	if got := len(c.shards[0].roots); got != maxIdle {
		t.Errorf("open roots after the last release: got = %d, want = %d", got, maxIdle)
	}
}

func TestRootCacheClose(t *testing.T) {
	t.Parallel()
	c, _ := rootCacheTestTree(t, 2, 4)
	r, release, err := c.Get(rootCacheTestDir(0))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	release()
	c.Close()
	if _, err := r.Stat("f.txt"); err == nil {
		t.Error("root after Close: got it open, want it closed")
	}
	if len(c.shards[0].roots) != 0 || c.shards[0].idle.Len() != 0 {
		t.Errorf("after Close: got %d open and %d idle, want none", len(c.shards[0].roots), c.shards[0].idle.Len())
	}
	var nilCache *RootCache
	nilCache.Close()
}

func TestNewRootCacheShardsWithinTheBound(t *testing.T) {
	t.Parallel()
	tests := []struct {
		maxIdle, wantShards, wantPerShard int
	}{
		{maxIdle: 1024, wantShards: rootCacheShards, wantPerShard: 1024 / rootCacheShards},
		{maxIdle: 10, wantShards: 10, wantPerShard: 1},
		{maxIdle: 0, wantShards: 1, wantPerShard: 1},
	}
	for _, tt := range tests {
		c := NewRootCache(nil, tt.maxIdle)
		if len(c.shards) != tt.wantShards || c.shards[0].maxIdle != tt.wantPerShard {
			t.Errorf("NewRootCache(%d): got %d shards of %d idle, want %d of %d", tt.maxIdle, len(c.shards), c.shards[0].maxIdle, tt.wantShards, tt.wantPerShard)
		}
	}
}

func TestRootCacheShardsKeepEachDirectoryInOnePlace(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for i := range 8 {
		if err := MkdirAllIn(dir, rootCacheTestDir(i), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()
	c := NewRootCache(root.OpenRoot, 1024)
	defer c.Close()
	for i := range 8 {
		r1, release1, err := c.Get(rootCacheTestDir(i))
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		r2, release2, err := c.Get(rootCacheTestDir(i))
		if err != nil || r2 != r1 {
			t.Errorf("second Get of %s: got = (%p, %v), want the same root %p", rootCacheTestDir(i), r2, err, r1)
		}
		release1()
		release2()
	}
}

func TestRootCacheCloseWaitsForRootsInUse(t *testing.T) {
	t.Parallel()
	c, opened := rootCacheTestTree(t, 1, 4)
	held, releaseHeld, err := c.Get(rootCacheTestDir(0))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	c.Close()
	if _, err := held.Stat("f.txt"); err != nil {
		t.Errorf("root in use after Close: got err = %v, want it open", err)
	}
	fresh, releaseFresh, err := c.Get(rootCacheTestDir(0))
	if err != nil {
		t.Fatalf("Get after Close: %v", err)
	}
	defer releaseFresh()
	if fresh == held {
		t.Error("Get after Close: got the dropped root, want a new one")
	}
	if got := opened.Load(); got != 2 {
		t.Errorf("roots opened: got = %d, want = 2", got)
	}
	releaseHeld()
	if _, err := held.Stat("f.txt"); err == nil {
		t.Error("dropped root after its last use: got it open, want it closed")
	}
	if _, err := fresh.Stat("f.txt"); err != nil {
		t.Errorf("new root: got err = %v, want it open", err)
	}
}

// TestRootCacheKeepsIdleRootsWithinTheBudget changes the budget shared by
// every RootCache, so it does not run in parallel.
func TestRootCacheKeepsIdleRootsWithinTheBudget(t *testing.T) {
	c, _ := rootCacheTestTree(t, 4, 64)
	saved := idleRootBudget
	base := idleRoots.Load()
	idleRootBudget = func() int64 { return base + 2 }
	t.Cleanup(func() { idleRootBudget = saved })

	roots := make([]*os.Root, 4)
	releases := make([]func(), 4)
	for i := range roots {
		r, release, err := c.Get(rootCacheTestDir(i))
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		roots[i], releases[i] = r, release
	}
	for _, release := range releases {
		release()
	}
	if got := idleRoots.Load() - base; got != 2 {
		t.Errorf("idle roots: got = %d, want = 2", got)
	}
	for i, r := range roots {
		_, err := r.Stat("f.txt")
		if open, want := err == nil, i >= 2; open != want {
			t.Errorf("root %d open: got = %v, want = %v (the most recently used stay)", i, open, want)
		}
	}
	c.Close()
	if got := idleRoots.Load(); got != base {
		t.Errorf("idle roots after Close: got = %d, want = %d", got, base)
	}
}

func TestIdleRootBudget(t *testing.T) {
	t.Parallel()
	limit, budget := openFileLimit(), idleRootBudget()
	if limit < 1 {
		t.Errorf("openFileLimit: got = %d, want a positive limit", limit)
	}
	if budget < 16 || budget > 2048 || (limit >= 64 && budget > limit/4) {
		t.Errorf("idleRootBudget: got = %d, want within [16, 2048] and at most a quarter of the limit %d", budget, limit)
	}
}

// dirRootsTestTree returns a root on a temporary directory holding top.txt,
// a/b/f.txt, and a symlink a/up to the directory b2 beside a, and DirRoots
// on it.
func dirRootsTestTree(t *testing.T) (string, *os.Root, *DirRoots) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"top.txt":                         "top",
		filepath.Join("a", "b", "f.txt"):  "f",
		filepath.Join("b2", "g.txt"):      "g",
		filepath.Join("a", "c", "h.txt"):  "h",
		filepath.Join("a", "c", "d", "i"): "i",
	} {
		if err := MkdirAllIn(dir, filepath.Dir(name), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := WriteFileIn(dir, name, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	if err := root.Symlink(filepath.Join("..", "b2"), filepath.Join("a", "up")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	d := NewDirRoots(root, 16)
	t.Cleanup(func() {
		d.Close()
		_ = root.Close()
	})
	return dir, root, d
}

func TestDirRootsParent(t *testing.T) {
	t.Parallel()
	_, root, d := dirRootsTestTree(t)
	tests := []struct {
		name     string
		wantBase string
		wantRoot bool // the root itself
		wantBody string
	}{
		{name: "top.txt", wantBase: "top.txt", wantRoot: true, wantBody: "top"},
		{name: filepath.Join("a", "b", "f.txt"), wantBase: "f.txt", wantBody: "f"},
		{name: filepath.Join("a", "c", "d", "i"), wantBase: "i", wantBody: "i"},
		// The link leaves its parent but stays beneath the root, which
		// follows it.
		{name: filepath.Join("a", "up", "g.txt"), wantBase: "g.txt", wantBody: "g"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, base, release, err := d.Parent(tt.name)
			if err != nil {
				t.Fatalf("Parent: %v", err)
			}
			defer release()
			if base != tt.wantBase || (r == root) != tt.wantRoot {
				t.Errorf("Parent(%q): got = (root %v, %q), want = (root %v, %q)", tt.name, r == root, base, tt.wantRoot, tt.wantBase)
			}
			if got, err := r.ReadFile(base); err != nil || string(got) != tt.wantBody {
				t.Errorf("read: got = (%q, %v), want = (%q, nil)", got, err, tt.wantBody)
			}
		})
	}
	if _, _, _, err := d.Parent(filepath.Join("missing", "f.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Parent beneath a missing directory: got err = %v, want = %v", err, fs.ErrNotExist)
	}
	var nilRoots *DirRoots
	nilRoots.Close()
}

func TestDirRootsOpensThroughTheParentsRoot(t *testing.T) {
	t.Parallel()
	dir, root, d := dirRootsTestTree(t)
	_, release, err := d.Dir("a")
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}
	defer release()
	// Once a's root is open, a/c is reached through it, and so in the
	// directory a named when its root was opened.
	if err := root.Rename("a", "moved"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := MkdirAllIn(dir, filepath.Join("a", "c"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r, releaseC, err := d.Dir(filepath.Join("a", "c"))
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}
	defer releaseC()
	if got, err := r.ReadFile("h.txt"); err != nil || string(got) != "h" {
		t.Errorf("read through a/c: got = (%q, %v), want = (%q, nil)", got, err, "h")
	}
}

func TestDirRootsReportsUnreachableDirectoriesAsTheRootDoes(t *testing.T) {
	t.Parallel()
	_, root, d := dirRootsTestTree(t)
	if _, release, err := d.Dir(filepath.Join("a", "c")); err == nil {
		release()
	}
	for _, dir := range []string{
		filepath.Join("missing", "x", "y"),
		filepath.Join("a", "missing"),
		filepath.Join("a", "c", "missing", "z"),
		"top.txt",
		filepath.Join("a", "c", "h.txt", "x"),
	} {
		_, _, got := d.Dir(dir)
		_, want := root.OpenRoot(dir)
		if got == nil || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("Dir(%q) error: got = %v, want = %v", dir, got, want)
		}
	}
}

func TestRootCacheNeverClosesARootTakenAgain(t *testing.T) {
	t.Parallel()
	c, _ := rootCacheTestTree(t, 4, 1)
	first, releaseFirst, err := c.Get(rootCacheTestDir(0))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	releaseFirst()
	// Taken again from the idle roots, twice, and released once: still in
	// use.
	held, releaseHeld, err := c.Get(rootCacheTestDir(0))
	if err != nil || held != first {
		t.Fatalf("Get of an idle root: got = (%p, %v), want = (%p, nil)", held, err, first)
	}
	_, releaseAgain, err := c.Get(rootCacheTestDir(0))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	releaseAgain()
	for i := 1; i < 4; i++ {
		_, release, err := c.Get(rootCacheTestDir(i))
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		release()
	}
	if _, err := held.Stat("f.txt"); err != nil {
		t.Errorf("root in use while others went idle: got err = %v, want it open", err)
	}
	releaseHeld()
	if got := c.shards[0].idle.Len(); got != 1 {
		t.Errorf("idle roots: got = %d, want = 1", got)
	}
}

func TestRootCacheSharesARootOpenedTwiceAtOnce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := MkdirAllIn(dir, "d", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	// Both callers miss, and neither open returns until both have started.
	var (
		mu     sync.Mutex
		opened []*os.Root
		both   sync.WaitGroup
	)
	both.Add(2)
	c := newShardedRootCache(func(dir string) (*os.Root, error) {
		both.Done()
		both.Wait()
		r, err := root.OpenRoot(dir)
		mu.Lock()
		opened = append(opened, r)
		mu.Unlock()
		return r, err
	}, 4, 1)
	t.Cleanup(c.Close)

	got := make([]*os.Root, 2)
	releases := make([]func(), 2)
	var wg sync.WaitGroup
	for i := range got {
		wg.Go(func() {
			r, release, err := c.Get("d")
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			got[i], releases[i] = r, release
		})
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	if got[0] != got[1] {
		t.Fatalf("roots: got %p and %p, want one root for both", got[0], got[1])
	}
	for _, r := range opened {
		_, err := r.Stat(".")
		if open, want := err == nil, r == got[0]; open != want {
			t.Errorf("root %p open: got = %v, want = %v (only the shared root stays)", r, open, want)
		}
	}
	releases[0]()
	if _, err := got[0].Stat("."); err != nil {
		t.Errorf("root after one of two releases: got err = %v, want it open", err)
	}
	releases[1]()
	if got := c.shards[0].idle.Len(); got != 1 {
		t.Errorf("idle roots after both releases: got = %d, want = 1", got)
	}
}

// TestRootCacheCountsIdleRoots changes the budget shared by every RootCache,
// so it does not run in parallel.
func TestRootCacheCountsIdleRoots(t *testing.T) {
	c, _ := rootCacheTestTree(t, 2, 4)
	other, _ := rootCacheTestTree(t, 2, 4)
	base := idleRoots.Load()
	idle := func(want int64, what string) {
		t.Helper()
		if got := idleRoots.Load() - base; got != want {
			t.Errorf("idle roots %s: got = %d, want = %d", what, got, want)
		}
	}
	r, release, err := c.Get(rootCacheTestDir(0))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	release()
	idle(1, "after a release")
	if _, release, err = c.Get(rootCacheTestDir(0)); err != nil {
		t.Fatalf("Get: %v", err)
	}
	idle(0, "with the root taken again")
	release()
	idle(1, "after releasing it again")

	// Over the budget, a cache closes its own idle roots, even every one of
	// them, while other caches keep theirs.
	for i := range 2 {
		_, release, err := other.Get(rootCacheTestDir(i))
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		release()
	}
	idle(3, "in both caches")
	saved := idleRootBudget
	idleRootBudget = func() int64 { return base + 1 }
	t.Cleanup(func() { idleRootBudget = saved })
	last, release, err := c.Get(rootCacheTestDir(1))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	release()
	idle(2, "after closing its own")
	for _, root := range []*os.Root{r, last} {
		if _, err := root.Stat("f.txt"); err == nil {
			t.Error("idle root of the cache over the budget: got it open, want it closed")
		}
	}
	if got := c.shards[0].idle.Len(); got != 0 {
		t.Errorf("idle roots of the cache over the budget: got = %d, want = 0", got)
	}
	other.Close()
	idle(0, "after closing the other cache")
}
