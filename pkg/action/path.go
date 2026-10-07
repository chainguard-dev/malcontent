// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
)

// walkScanPath walks rootPath, through the walk root it opens, and returns
// that root and the files beneath it with their names and sizes. A symlink
// given as rootPath is followed; symlinks beneath it, and everything below a
// .git directory, are skipped, and entries that cannot be read are logged and
// passed over. A missing rootPath yields no files and no walk root.
func walkScanPath(ctx context.Context, rootPath string) (*walkRoot, []walkedFile, error) {
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	logger := clog.FromContext(ctx)

	// Follow symlink if provided at the root
	root, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		// If the target does not exist, log the error but return gracefully
		// This is useful when scanning -compat packages
		if errors.Is(err, fs.ErrNotExist) {
			logger.Debugf("symlink target does not exist: %s", err.Error())
			return nil, nil, nil
		}
		// A /proc/XXX/exe link that cannot be resolved is itself a symlink,
		// which the walk would skip.
		if strings.HasPrefix(rootPath, "/proc/") {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("eval %q: %w", rootPath, err)
	}

	w, start, err := openWalkRoot(root)
	if err != nil {
		// As with any entry the walk cannot read.
		logger.Debugf("error: %s: %s", root, err)
		return nil, nil, nil
	}
	info, err := w.root.Stat(start)
	if err != nil {
		logger.Debugf("error: %s: %s", filepath.Join(w.base, start), err)
		return w, nil, nil
	}
	sw := &scanWalk{base: w.base, slots: make(chan struct{}, walkWorkers-1)}
	var files []walkedFile
	for _, f := range sw.visit(w.root, start, filepath.ToSlash(start), fs.FileInfoToDirEntry(info)) {
		if f.err != nil {
			logger.Debugf("error: %s: %s", f.path, f.err)
			continue
		}
		files = append(files, f.file)
	}
	return w, files, nil
}

// walkWorkers bounds the directories a walk of a scan path reads at once.
const walkWorkers = 16

// scanWalk walks a scan path as file.WalkDir would, reading directories in
// parallel and collecting what it finds in the order file.WalkDir visits it.
type scanWalk struct {
	base string // the walk root's directory
	// slots bounds the goroutines reading directories besides the caller's.
	slots chan struct{}
}

// walkFound is a file a walk found, or an error to log for path.
type walkFound struct {
	file walkedFile
	path string
	err  error
}

// visit returns what the entry d holds, as walkScanPath reports it: d is
// elem beneath parent, and name, slash-separated, beneath the walk root.
// Symlinks, and everything below a .git directory, are passed over.
func (sw *scanWalk) visit(parent *os.Root, elem, name string, d fs.DirEntry) []walkFound {
	path := filepath.Join(sw.base, filepath.FromSlash(name))
	if !d.IsDir() {
		// Ignore symlinked directories like regular directories
		if strings.Contains(path, "/.git/") || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		f := walkedFile{path: path, name: filepath.FromSlash(name), regular: d.Type().IsRegular()}
		// A directory read through a root has each entry's FileInfo.
		if fi, err := d.Info(); err == nil {
			f.size = fi.Size()
		}
		return []walkFound{{file: f}}
	}
	// Nothing below a .git directory is reported, so skip it rather than
	// walking it. The exception is a .git directory named by the bare
	// relative path ".git", as when walking ".": its entries lack the
	// "/.git/" checked above, so they are reported.
	if d.Name() == ".git" && path != ".git" {
		return nil
	}

	dir, err := parent.OpenRoot(elem)
	var entries []fs.DirEntry
	if err == nil {
		defer dir.Close()
		entries, err = file.ReadDir(dir)
	}
	var found []walkFound
	if err != nil {
		found = append(found, walkFound{path: path, err: err})
	}
	parts := make([][]walkFound, len(entries))
	var wg sync.WaitGroup
	for i, e := range entries {
		child := e.Name()
		if name != "." {
			child = name + "/" + child
		}
		if e.IsDir() && sw.tryAcquire() {
			wg.Go(func() {
				defer func() { <-sw.slots }()
				parts[i] = sw.visit(dir, e.Name(), child, e)
			})
			continue
		}
		parts[i] = sw.visit(dir, e.Name(), child, e)
	}
	wg.Wait()
	for _, p := range parts {
		found = append(found, p...)
	}
	return found
}

// tryAcquire takes a slot for another goroutine, when one is free.
func (sw *scanWalk) tryAcquire() bool {
	select {
	case sw.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// CleanPath removes the temporary directory prefix from the path.
// It only removes the prefix if it's at a directory boundary to avoid
// partial matches (e.g., "/tmp/extract" should not match "/tmp/extract2/file").
func CleanPath(path string, prefix string) string {
	// Check if path starts with prefix
	if !strings.HasPrefix(path, prefix) {
		return formatPath(path)
	}

	// If path equals prefix exactly, return empty
	if len(path) == len(prefix) {
		return ""
	}

	// Only strip if the next character is a path separator (directory boundary)
	remainder := path[len(prefix):]
	if remainder[0] == '/' || remainder[0] == '\\' {
		return formatPath(remainder)
	}

	// Partial match (e.g., prefix="/tmp/extract" but path="/tmp/extract2/file")
	// Don't strip anything
	return formatPath(path)
}

// formatPath formats the path for display.
func formatPath(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

// walkRoot is the root through which the files found by walking a scan path
// are read: the scan path, with symlinks resolved, or the directory holding
// it when it is not a directory.
type walkRoot struct {
	root *os.Root
	base string // the root's directory
	dirs *file.DirRoots
}

// maxIdleDirRoots bounds the directory roots kept open beneath a walk root,
// or an archive's extraction directory, while no scan uses them.
const maxIdleDirRoots = 1024

// openWalkRoot opens the walk root of scanPath and returns it with the name
// of scanPath beneath it: "." for a directory, which is the root, and its
// last element for anything else.
func openWalkRoot(scanPath string) (*walkRoot, string, error) {
	fi, err := file.Stat(scanPath)
	if err != nil {
		return nil, "", err
	}
	base, start := scanPath, "."
	if !fi.IsDir() {
		base, start = filepath.Dir(scanPath), filepath.Base(scanPath)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, "", err
	}
	return &walkRoot{root: root, base: base, dirs: file.NewDirRoots(root, maxIdleDirRoots)}, start, nil
}

// name returns the name of path, a walked file, beneath the walk root.
func (w *walkRoot) name(path string) (string, error) {
	return filepath.Rel(w.base, path)
}

// close closes the walk root. It is safe to call on nil.
func (w *walkRoot) close() {
	if w != nil {
		w.dirs.Close()
		_ = w.root.Close()
	}
}
