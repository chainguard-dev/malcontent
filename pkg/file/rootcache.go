// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"container/list"
	"errors"
	"hash/maphash"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// rootCacheShards is the most shards a RootCache divides its roots among, so
// that concurrent callers seldom wait on the same lock.
const rootCacheShards = 64

// idleRoots counts the roots every RootCache keeps open while no caller uses
// them. Together they stay within idleRootBudget, so that idle roots never
// take the descriptors that open files need.
var idleRoots atomic.Int64

// idleRootBudget is the most roots all RootCaches together keep idle: a
// quarter of the files the process may have open, within [16, 2048].
var idleRootBudget = sync.OnceValue(func() int64 {
	return min(max(openFileLimit()/4, 16), 2048)
})

var reserveOnce sync.Once

// ReserveDescriptors makes room, once and in the background, for the roots
// that RootCaches keep idle and as many files again. Linux grows a process's
// descriptor table by doubling it as descriptors are opened, and while it
// does, every thread opening a file waits for an RCU grace period, tens of
// milliseconds on a machine with many processors. Directories kept open
// would otherwise make the table grow several times during a scan, stalling
// every worker each time.
func ReserveDescriptors() {
	reserveOnce.Do(func() { go growTableForIdleRoots() })
}

// growTableForIdleRoots grows the descriptor table to hold the roots that
// RootCaches keep idle and as many files again.
func growTableForIdleRoots() {
	growDescriptorTable(2 * idleRootBudget())
}

// RootCache keeps roots on directories open for reuse, so that the many files
// in one directory are reached through one root instead of a root, or a walk
// down from one, per file. Each such walk opens and closes every directory on
// the way, and concurrent scans below the same directories contend on them.
// Roots in use are never closed; of the rest, the least recently used beyond
// the cache's bound, or beyond what all caches may keep idle together, are.
// It is safe for concurrent use.
type RootCache struct {
	open   func(dir string) (*os.Root, error)
	seed   maphash.Seed
	shards []rootCacheShard
}

// rootCacheShard holds the roots on the directories that hash to it.
type rootCacheShard struct {
	maxIdle int
	mu      sync.Mutex
	roots   map[string]*cachedRoot
	// idle holds the roots no caller uses, least recently used first.
	idle list.List
}

// cachedRoot is a root on one directory and the callers using it.
type cachedRoot struct {
	dir  string
	r    *os.Root
	refs int
	elem *list.Element // in idle while refs is zero
}

// NewRootCache returns a RootCache that opens the root on a directory with
// open and keeps at most maxIdle roots open while no caller uses them.
func NewRootCache(open func(dir string) (*os.Root, error), maxIdle int) *RootCache {
	return newShardedRootCache(open, maxIdle, min(rootCacheShards, max(maxIdle, 1)))
}

// newShardedRootCache returns a RootCache divided among shards, each keeping
// an equal share of maxIdle idle roots.
func newShardedRootCache(open func(dir string) (*os.Root, error), maxIdle, shards int) *RootCache {
	c := &RootCache{open: open, seed: maphash.MakeSeed(), shards: make([]rootCacheShard, shards)}
	for i := range c.shards {
		c.shards[i] = rootCacheShard{maxIdle: max(maxIdle/shards, 1), roots: map[string]*cachedRoot{}}
	}
	return c
}

// shard returns the shard holding dir.
func (c *RootCache) shard(dir string) *rootCacheShard {
	return &c.shards[maphash.String(c.seed, dir)%uint64(len(c.shards))]
}

// Get returns the root on dir and the function that ends the caller's use of
// it.
func (c *RootCache) Get(dir string) (*os.Root, func(), error) {
	s := c.shard(dir)
	if e := s.use(dir); e != nil {
		return e.r, func() { s.release(e) }, nil
	}
	r, err := c.open(dir)
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	e, ok := s.roots[dir]
	if ok {
		// Another caller opened it meanwhile.
		s.acquire(e)
		s.mu.Unlock()
		_ = r.Close()
		return e.r, func() { s.release(e) }, nil
	}
	e = &cachedRoot{dir: dir, r: r, refs: 1}
	s.roots[dir] = e
	s.mu.Unlock()
	return r, func() { s.release(e) }, nil
}

// use returns the open root on dir, counting the caller as a user, or nil.
func (s *rootCacheShard) use(dir string) *cachedRoot {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.roots[dir]
	if !ok {
		return nil
	}
	s.acquire(e)
	return e
}

// acquire counts a user of e. s.mu must be held.
func (s *rootCacheShard) acquire(e *cachedRoot) {
	if e.refs == 0 {
		s.idle.Remove(e.elem)
		e.elem = nil
		idleRoots.Add(-1)
	}
	e.refs++
}

// release ends one use of e. A root that Close dropped while in use is closed
// after its last use; any other goes idle, and the least recently used idle
// roots beyond the bounds are closed.
func (s *rootCacheShard) release(e *cachedRoot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.refs--
	if e.refs > 0 {
		return
	}
	if s.roots[e.dir] != e {
		_ = e.r.Close()
		return
	}
	e.elem = s.idle.PushBack(e)
	n := idleRoots.Add(1)
	for s.idle.Len() > 0 && (s.idle.Len() > s.maxIdle || n > idleRootBudget()) {
		old, _ := s.idle.Remove(s.idle.Front()).(*cachedRoot)
		delete(s.roots, old.dir)
		_ = old.r.Close()
		n = idleRoots.Add(-1)
	}
}

// Close closes every root: the idle ones at once, and the ones in use after
// their last use. Later calls to Get open roots anew. It is safe to call on
// nil.
func (c *RootCache) Close() {
	if c == nil {
		return
	}
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for dir, e := range s.roots {
			delete(s.roots, dir)
			if e.refs == 0 {
				_ = e.r.Close()
			}
		}
		idleRoots.Add(-int64(s.idle.Len()))
		s.idle.Init()
		s.mu.Unlock()
	}
}

// DirRoots keeps roots on the directories beneath a root open for reuse, so
// that a file is one lookup in its directory rather than one per element of
// its path. A directory not yet open is opened from its parent's root, which
// is itself reused, so that it too costs one lookup. It is safe for
// concurrent use.
type DirRoots struct {
	root  *os.Root
	cache *RootCache
}

// NewDirRoots returns a DirRoots for the directories beneath root that keeps
// at most maxIdle of their roots open while no caller uses them.
func NewDirRoots(root *os.Root, maxIdle int) *DirRoots {
	d := &DirRoots{root: root}
	d.cache = NewRootCache(d.open, maxIdle)
	return d
}

// open opens the root on dir, a directory beneath the root, through the root
// on its parent, so that every directory is reached as the root reaches it
// but with one lookup. A directory missing from its parent, or beneath a
// missing parent, is missing from the root too, and is reported as the root
// reports it. Any other failure, as for a symlink that leaves the parent but
// not the root, is left to the root.
func (d *DirRoots) open(dir string) (*os.Root, error) {
	parent := filepath.Dir(dir)
	if parent == "." {
		return d.root.OpenRoot(dir)
	}
	pr, release, err := d.cache.Get(parent)
	if err == nil {
		var r *os.Root
		r, err = pr.OpenRoot(filepath.Base(dir))
		release()
		if err == nil {
			return r, nil
		}
	}
	var pe *fs.PathError
	if errors.As(err, &pe) && errors.Is(pe.Err, fs.ErrNotExist) {
		return nil, &fs.PathError{Op: pe.Op, Path: dir, Err: pe.Err}
	}
	return d.root.OpenRoot(dir)
}

// Dir returns the root on dir, a directory beneath the root, and the function
// that ends the caller's use of it. The directory "." is the root itself.
func (d *DirRoots) Dir(dir string) (*os.Root, func(), error) {
	if dir == "." {
		return d.root, func() {}, nil
	}
	return d.cache.Get(dir)
}

// Parent returns the root on the directory holding name, a path beneath the
// root, name's last element, and the function that ends the caller's use of
// the root.
func (d *DirRoots) Parent(name string) (*os.Root, string, func(), error) {
	dir, base := filepath.Split(name)
	r, release, err := d.Dir(filepath.Clean(dir))
	if err != nil {
		return nil, "", nil, err
	}
	return r, base, release, nil
}

// Close closes the roots on the directories, but not the root itself, as
// RootCache.Close does. It is safe to call on nil.
func (d *DirRoots) Close() {
	if d != nil {
		d.cache.Close()
	}
}
