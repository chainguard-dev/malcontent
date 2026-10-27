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

// openScanPath opens the walk root of rootPath, following rootPath when it
// is a symlink, and returns it with the name of rootPath beneath it. A scan
// path that does not exist, or whose walk root cannot be opened, is an error
// wrapping the cause, such as fs.ErrNotExist or fs.ErrPermission. A dangling
// symlink, and a /proc path that cannot be resolved, as for a process that
// has exited, yield no walk root and no error.
func openScanPath(ctx context.Context, rootPath string) (*walkRoot, string, error) {
	logger := clog.FromContext(ctx)
	root, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		if strings.HasPrefix(rootPath, "/proc/") {
			logger.Debugf("skipping %s: %v", rootPath, err)
			return nil, "", nil
		}
		if errors.Is(err, fs.ErrNotExist) && danglingSymlink(rootPath) {
			// Useful when scanning -compat packages, whose links point into
			// packages that are not installed.
			logger.Debugf("symlink target does not exist: %s", err.Error())
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("scan path %q: %w", rootPath, err)
	}
	w, start, err := openWalkRoot(root)
	if err != nil {
		return nil, "", fmt.Errorf("scan path %q: %w", rootPath, err)
	}
	return w, start, nil
}

// danglingSymlink reports whether path, which the caller found leads
// nowhere, is a symlink.
func danglingSymlink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&fs.ModeSymlink != 0
}

// walkFileHook, when non-nil, is invoked as the walk of a scan path reaches
// each file. It exists solely so tests can observe the walk at its deepest
// point; production leaves it nil and the call is a no-op.
var walkFileHook func()

// walkWorkers bounds the directories a walk of a scan path reads at once.
const walkWorkers = 16

// walkInto walks the tree rooted at start beneath w, from up to walkWorkers
// goroutines, and calls emit, concurrently, with each file it finds, until
// ctx ends. Symlinks below start are passed over, as are the object stores
// of git repositories and the pseudo filesystems, such as proc and sysfs,
// mounted below start. Entries that cannot be read are logged and passed
// over.
func walkInto(ctx context.Context, w *walkRoot, start string, emit func(walkedFile)) {
	sw := &scanWalk{
		ctx:    ctx,
		logger: clog.FromContext(ctx),
		base:   w.base,
		slots:  make(chan struct{}, walkWorkers-1),
		emit:   emit,
	}
	sw.walk(file.NewWalker(w.root, filepath.ToSlash(start)))
}

// scanWalk walks a scan path as file.WalkDir would, handing directories to
// other goroutines while slots allow.
type scanWalk struct {
	ctx    context.Context
	logger *clog.Logger
	base   string // the walk root's directory
	// slots bounds the goroutines walking directories besides the caller's.
	slots chan struct{}
	emit  func(walkedFile)
}

// walk emits what w yields, as walkInto describes, and closes w.
func (sw *scanWalk) walk(w *file.Walker) {
	defer w.Close()
	var wg sync.WaitGroup
	defer wg.Wait()
	w.SkipPseudoFilesystems()
	for w.Next() {
		if sw.ctx.Err() != nil {
			return
		}
		name := w.Path()
		path := filepath.Join(sw.base, filepath.FromSlash(name))
		if err := w.Err(); err != nil {
			sw.skipped(path, err)
			continue
		}
		d := w.Entry()
		if !d.IsDir() {
			// Ignore symlinked directories like regular directories
			if d.Type()&fs.ModeSymlink != 0 {
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
			sw.emit(f)
			continue
		}
		if name != "." && gitObjects(path) {
			w.SkipDir()
			continue
		}
		if !sw.tryAcquire() {
			continue
		}
		dir, err := w.Detach()
		if err != nil {
			<-sw.slots
			sw.skipped(path, err)
			continue
		}
		wg.Go(func() {
			defer func() { <-sw.slots }()
			sw.walk(file.NewDirWalker(dir, name, d))
		})
	}
}

// skipped logs the entry at path that the walk passes over because of err.
func (sw *scanWalk) skipped(path string, err error) {
	if errors.Is(err, file.ErrPseudoFS) {
		sw.logger.Debugf("skipping %s: %v", path, err)
		return
	}
	sw.logger.Warnf("skipping %s: %v", path, err)
}

// gitObjects reports whether dir is the object store of a git repository: a
// directory named objects in one named .git. Its loose objects and packs are
// compressed repository content, which scanning would only extract; the rest
// of .git, such as hooks and config, is scanned.
func gitObjects(dir string) bool {
	return filepath.Base(dir) == "objects" && filepath.Base(filepath.Dir(dir)) == ".git"
}

// inGitObjects reports whether rel, a path within an archive, lies in the
// object store of a git repository the archive holds.
func inGitObjects(rel string) bool {
	for d := filepath.Dir(rel); d != "." && d != filepath.Dir(d); d = filepath.Dir(d) {
		if gitObjects(d) {
			return true
		}
	}
	return false
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
	if os.IsPathSeparator(remainder[0]) {
		return formatPath(remainder)
	}

	// Partial match (e.g., prefix="/tmp/extract" but path="/tmp/extract2/file")
	// Don't strip anything
	return formatPath(path)
}

// formatPath formats the path for display, with slashes between its
// elements. Only the platform's separator is replaced: elsewhere a backslash
// is part of a file's name, so files named `a\b` and `a/b` keep distinct
// keys.
func formatPath(path string) string {
	return filepath.ToSlash(path)
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
