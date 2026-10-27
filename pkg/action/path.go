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
	// The walk reports a start it cannot examine as it reports any entry.
	sw := &scanWalk{base: w.base, slots: make(chan struct{}, walkWorkers-1)}
	var files []walkedFile
	for _, f := range sw.walk(file.NewWalker(w.root, filepath.ToSlash(start))) {
		if f.err != nil {
			logger.Debugf("error: %s: %s", f.path, f.err)
			continue
		}
		files = append(files, f.file)
	}
	return w, files, nil
}

// walkFileHook, when non-nil, is invoked as the walk of a scan path reaches
// each file. It exists solely so tests can observe the walk at its deepest
// point; production leaves it nil and the call is a no-op.
var walkFileHook func()

// walkWorkers bounds the directories a walk of a scan path reads at once.
const walkWorkers = 16

// scanWalk walks a scan path as file.WalkDir would, handing directories to
// other goroutines while slots allow and collecting what it finds in the
// order file.WalkDir visits it.
type scanWalk struct {
	base string // the walk root's directory
	// slots bounds the goroutines walking directories besides the caller's.
	slots chan struct{}
}

// walkFound is a file a walk found, or an error to log for path.
type walkFound struct {
	file walkedFile
	path string
	err  error
}

// walkPart is what a directory handed to another goroutine holds, and where
// among the findings of the walk that handed it over it belongs.
type walkPart struct {
	at    int
	found []walkFound
}

// walk returns what w yields, as walkScanPath reports it, and closes w.
// Symlinks, and everything below a .git directory, are passed over.
func (sw *scanWalk) walk(w *file.Walker) []walkFound {
	defer w.Close()
	var found []walkFound
	var parts []*walkPart
	var wg sync.WaitGroup
	for w.Next() {
		name := w.Path()
		path := filepath.Join(sw.base, filepath.FromSlash(name))
		if err := w.Err(); err != nil {
			found = append(found, walkFound{path: path, err: err})
			continue
		}
		d := w.Entry()
		if !d.IsDir() {
			// Ignore symlinked directories like regular directories
			if strings.Contains(path, "/.git/") || d.Type()&fs.ModeSymlink != 0 {
				continue
			}
			if hook := walkFileHook; hook != nil {
				hook()
			}
			f := walkedFile{path: path, name: filepath.FromSlash(name), regular: d.Type().IsRegular()}
			// A directory read through a root has each entry's FileInfo.
			if fi, err := d.Info(); err == nil {
				f.size = fi.Size()
			}
			found = append(found, walkFound{file: f})
			continue
		}
		// Nothing below a .git directory is reported, so skip it rather than
		// walking it. The exception is a .git directory named by the bare
		// relative path ".git", as when walking ".": its entries lack the
		// "/.git/" checked above, so they are reported.
		if d.Name() == ".git" && path != ".git" {
			w.SkipDir()
			continue
		}
		if !sw.tryAcquire() {
			continue
		}
		dir, err := w.Detach()
		if err != nil {
			<-sw.slots
			found = append(found, walkFound{path: path, err: err})
			continue
		}
		p := &walkPart{at: len(found)}
		parts = append(parts, p)
		wg.Go(func() {
			defer func() { <-sw.slots }()
			p.found = sw.walk(file.NewDirWalker(dir, name, d))
		})
	}
	wg.Wait()
	return splice(found, parts)
}

// splice returns found with the findings of each part inserted where it
// belongs.
func splice(found []walkFound, parts []*walkPart) []walkFound {
	if len(parts) == 0 {
		return found
	}
	n := len(found)
	for _, p := range parts {
		n += len(p.found)
	}
	out := make([]walkFound, 0, n)
	prev := 0
	for _, p := range parts {
		out = append(out, found[prev:p.at]...)
		out = append(out, p.found...)
		prev = p.at
	}
	return append(out, found[prev:]...)
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
