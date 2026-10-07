// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// benchTree returns a root on a temporary directory holding files files
// spread over dirs directories four levels deep, and the files' names.
func benchTree(b *testing.B, dirs, files int) (*os.Root, []string) {
	b.Helper()
	dir := b.TempDir()
	names := make([]string, files)
	for i := range files {
		names[i] = filepath.Join("a", "b", fmt.Sprintf("d%d", i%dirs), "e", fmt.Sprintf("f%d", i))
		if err := MkdirAllIn(dir, filepath.Dir(names[i]), 0o700); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		if err := WriteFileIn(dir, names[i], []byte("x"), 0o600); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		b.Fatalf("OpenRoot: %v", err)
	}
	b.Cleanup(func() { _ = root.Close() })
	return root, names
}

// BenchmarkOpenBeneathRoot opens files five levels beneath a root from many
// goroutines, through the root itself, which opens every directory on the
// way, and through DirRoots, which keeps their roots open.
func BenchmarkOpenBeneathRoot(b *testing.B) {
	root, names := benchTree(b, 64, 1024)
	d := NewDirRoots(root, 1024)
	b.Cleanup(d.Close)
	opens := []struct {
		name string
		open func(name string) (*os.File, error)
	}{
		{name: "root", open: root.Open},
		{name: "dirroots", open: func(name string) (*os.File, error) {
			r, base, release, err := d.Parent(name)
			if err != nil {
				return nil, err
			}
			defer release()
			return r.Open(base)
		}},
	}
	for _, o := range opens {
		b.Run(o.name, func(b *testing.B) {
			var next atomic.Int64
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					f, err := o.open(names[next.Add(1)%int64(len(names))])
					if err != nil {
						b.Errorf("open: %v", err)
						return
					}
					_ = f.Close()
				}
			})
		})
	}
}

// BenchmarkWalkDir walks a tree of 256 directories, each reached through its
// parent's root, against fs.WalkDir over the root's FS, which reaches every
// directory from the root.
func BenchmarkWalkDir(b *testing.B) {
	root, _ := benchTree(b, 256, 2048)
	walks := []struct {
		name string
		walk func(fs.WalkDirFunc) error
	}{
		{name: "file.WalkDir", walk: func(fn fs.WalkDirFunc) error { return WalkDir(root, ".", fn) }},
		{name: "fs.WalkDir", walk: func(fn fs.WalkDirFunc) error { return fs.WalkDir(root.FS(), ".", fn) }},
	}
	for _, w := range walks {
		b.Run(w.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				n := 0
				if err := w.walk(func(_ string, d fs.DirEntry, err error) error {
					if err == nil && !d.IsDir() {
						n++
					}
					return err
				}); err != nil || n != 2048 {
					b.Fatalf("walk: got = (%d files, %v), want = (2048, nil)", n, err)
				}
			}
		})
	}
}

// BenchmarkRootCacheGet takes and releases cached roots from many goroutines.
func BenchmarkRootCacheGet(b *testing.B) {
	root, names := benchTree(b, 64, 64)
	c := NewRootCache(root.OpenRoot, 1024)
	b.Cleanup(c.Close)
	var next atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, release, err := c.Get(filepath.Dir(names[next.Add(1)%int64(len(names))]))
			if err != nil {
				b.Errorf("Get: %v", err)
				return
			}
			release()
		}
	})
}
