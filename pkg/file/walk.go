// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"io/fs"
	"os"
)

// errNotWalkable reports a call to Detach for an entry that is not a
// directory to walk.
var errNotWalkable = errors.New("current entry is not a directory to walk")

// A Walker walks a tree beneath a root as fs.WalkDir walks it: depth first,
// in lexical order, with slash-separated paths, without following symlinks
// below where it starts, and reporting a directory it cannot read as a second
// entry for that directory, with the error. It yields one entry for each call
// to Next, without recursion, and lets go of a directory once it yields the
// directory's last entry, so that however deep the tree it holds one path and
// the roots of the directories that still have entries to yield. It opens
// each directory through its parent's root, so a directory costs one lookup
// however deep it lies. A Walker is not safe for concurrent use.
type Walker struct {
	path []byte      // the current entry's path
	d    fs.DirEntry // the current entry, nil when name could not be examined
	err  error       // why the current entry, a directory, could not be read

	// stack holds the directories with entries left to yield, innermost last.
	stack []walkFrame
	// inStack reports whether the current entry's directory is still on the
	// stack, as it is unless the entry was the directory's last.
	inStack bool
	// next is the directory the current entry names, read by the next call
	// to Next unless the caller skips or detaches it.
	next *walkDir
	// failed is the directory the current entry reports could not be read,
	// with whatever was read of it.
	failed *walkFrame
	// started reports whether the entry NewWalker starts with was yielded.
	started bool
	done    bool
}

// walkFrame is a directory and the entries it has left to yield.
type walkFrame struct {
	dir     *os.Root
	entries []fs.DirEntry
	prefix  int // the length of the directory's path, as its entries' paths begin
}

// walkDir is a directory yet to be read: dir when it is open, or elem
// beneath parent, which is closed once dir is opened when owned.
type walkDir struct {
	dir    *os.Root
	parent *os.Root
	owned  bool
	elem   string
	prefix int
}

// prefixOf returns how much of path the paths of the entries beneath it
// begin with: all of it, but none of ".", whose entries' paths are their
// names alone.
func prefixOf(path string) int {
	if path == "." {
		return 0
	}
	return len(path)
}

// NewWalker returns a Walker over the tree rooted at name beneath r, which
// it starts with, as fs.WalkDir starts with root. When name cannot be
// examined, the walk is that one entry, with the error and no DirEntry. The
// caller closes r, after closing the Walker.
func NewWalker(r *os.Root, name string) *Walker {
	w := &Walker{path: []byte(name)}
	info, err := r.Stat(name)
	if err != nil {
		w.err = err
		return w
	}
	w.d = fs.FileInfoToDirEntry(info)
	if w.d.IsDir() {
		w.next = &walkDir{parent: r, elem: name, prefix: prefixOf(name)}
	}
	return w
}

// NewDirWalker returns a Walker over the entries beneath dir, a directory
// whose entry is d, with paths beneath name. It does not yield dir itself,
// except as an entry with an error when dir cannot be read. The Walker owns
// dir and closes it.
func NewDirWalker(dir *os.Root, name string, d fs.DirEntry) *Walker {
	return &Walker{path: []byte(name), d: d, started: true, next: &walkDir{dir: dir, prefix: prefixOf(name)}}
}

// Next advances to the next entry and reports whether there is one.
func (w *Walker) Next() bool {
	if w.done {
		return false
	}
	if !w.started {
		w.started = true
		if w.d != nil || w.err != nil {
			return true
		}
	}
	if n := w.next; n != nil {
		w.next = nil
		if w.read(n) {
			return true
		}
	}
	if f := w.failed; f != nil {
		w.failed = nil
		w.push(*f)
	}
	return w.advance()
}

// read reads the directory n, keeping its entries for Next, and reports
// whether reading failed, which makes the failure the current entry.
func (w *Walker) read(n *walkDir) bool {
	dir := n.dir
	var err error
	if dir == nil {
		dir, err = n.parent.OpenRoot(n.elem)
		if n.owned {
			_ = n.parent.Close()
		}
	}
	var entries []fs.DirEntry
	if err == nil {
		entries, err = ReadDir(dir)
	}
	f := walkFrame{dir: dir, entries: entries, prefix: n.prefix}
	if err != nil {
		w.err, w.failed = err, &f
		return true
	}
	w.push(f)
	return false
}

// push keeps f for Next when it has entries to yield, and closes it when it
// does not.
func (w *Walker) push(f walkFrame) {
	if len(f.entries) == 0 {
		if f.dir != nil {
			_ = f.dir.Close()
		}
		return
	}
	w.stack = append(w.stack, f)
}

// pop drops the innermost directory, closing it.
func (w *Walker) pop() {
	i := len(w.stack) - 1
	_ = w.stack[i].dir.Close()
	w.stack[i] = walkFrame{}
	w.stack = w.stack[:i]
}

// advance makes the next entry of the innermost directory current. When it
// is the directory's last, the directory is dropped, and closed once the
// entry needs it no more.
func (w *Walker) advance() bool {
	w.err = nil
	if len(w.stack) == 0 {
		w.done = true
		return false
	}
	i := len(w.stack) - 1
	top := &w.stack[i]
	e := top.entries[0]
	top.entries = top.entries[1:]
	parent, prefix := top.dir, top.prefix
	last := len(top.entries) == 0
	if last {
		w.stack[i] = walkFrame{}
		w.stack = w.stack[:i]
	}

	w.path = w.path[:prefix]
	if prefix > 0 {
		w.path = append(w.path, '/')
	}
	w.path = append(w.path, e.Name()...)
	w.d, w.inStack = e, !last
	switch {
	case e.IsDir():
		w.next = &walkDir{parent: parent, owned: last, elem: e.Name(), prefix: len(w.path)}
	case last:
		_ = parent.Close()
	}
	return true
}

// Path returns the current entry's path.
func (w *Walker) Path() string { return string(w.path) }

// Entry returns the current entry, or nil when the entry NewWalker starts
// with could not be examined.
func (w *Walker) Entry() fs.DirEntry { return w.d }

// Err returns why the current entry could not be examined or, for a
// directory yielded a second time, read.
func (w *Walker) Err() error { return w.err }

// SkipDir skips what the current entry leads to, as returning fs.SkipDir to
// fs.WalkDir does: the entries of a directory, what was read of a directory
// that could not be read, and the rest of the directory holding anything
// else.
func (w *Walker) SkipDir() {
	switch {
	case w.next != nil:
		w.next.close()
		w.next = nil
	case w.failed != nil:
		if w.failed.dir != nil {
			_ = w.failed.dir.Close()
		}
		w.failed = nil
	case w.inStack:
		w.pop()
		w.inStack = false
	}
}

// Detach opens the directory the current entry names and returns its root
// instead of walking it. The caller closes the root.
func (w *Walker) Detach() (*os.Root, error) {
	n := w.next
	if n == nil {
		return nil, errNotWalkable
	}
	w.next = nil
	if n.dir != nil {
		return n.dir, nil
	}
	dir, err := n.parent.OpenRoot(n.elem)
	if n.owned {
		_ = n.parent.Close()
	}
	return dir, err
}

// close closes what n holds open.
func (n *walkDir) close() {
	switch {
	case n.dir != nil:
		_ = n.dir.Close()
	case n.owned:
		_ = n.parent.Close()
	}
}

// Close closes the roots the Walker holds. Later calls to Next report no
// entry.
func (w *Walker) Close() {
	if w.next != nil {
		w.next.close()
		w.next = nil
	}
	if w.failed != nil && w.failed.dir != nil {
		_ = w.failed.dir.Close()
	}
	w.failed = nil
	for len(w.stack) > 0 {
		w.pop()
	}
	w.done = true
}

// WalkDir walks the tree rooted at name beneath r as fs.WalkDir walks
// r.FS(): in lexical order, calling fn with slash-separated paths, without
// following symlinks below name, and with the same handling of errors,
// fs.SkipDir, and fs.SkipAll. It opens each directory relative to its parent
// rather than from r, so a directory costs one lookup however deep it lies,
// and holds memory in proportion to the length of a path rather than to its
// square.
func WalkDir(r *os.Root, name string, fn fs.WalkDirFunc) error {
	w := NewWalker(r, name)
	defer w.Close()
	for w.Next() {
		err := fn(w.Path(), w.Entry(), w.Err())
		switch {
		case err == nil:
		case errors.Is(err, fs.SkipDir):
			w.SkipDir()
		case errors.Is(err, fs.SkipAll):
			return nil
		default:
			return err
		}
	}
	return nil
}
