// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// maxIdleEntryRoots bounds the directory roots an extraction keeps open while
// no entry uses them.
const maxIdleEntryRoots = 1024

// entryRoots reaches the directories one extraction writes entries to
// through roots kept open from entry to entry, so that creating a file, or
// examining the path IsValidPath checks, is one lookup in its directory
// rather than one per element of its path. Removing or replacing an entry can
// change where the names beneath it lead, so the extraction closes the roots
// after doing so.
type entryRoots struct {
	root *os.Root
	dirs *file.DirRoots
}

func newEntryRoots(root *os.Root) *entryRoots {
	return &entryRoots{root: root, dirs: file.NewDirRoots(root, maxIdleEntryRoots)}
}

// createFile creates or truncates name beneath the root, as createFile does.
func (er *entryRoots) createFile(name string) (*os.File, error) {
	r, base, release, err := er.dirs.Parent(name)
	if errors.Is(err, fs.ErrNotExist) {
		if err := er.root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return nil, fmt.Errorf("failed to create parent directory: %w", err)
		}
		r, base, release, err = er.dirs.Parent(name)
	}
	if err == nil {
		out, err := r.OpenFile(base, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		release()
		if err == nil {
			return out, nil
		}
		if errors.Is(err, fs.ErrExist) {
			// createFile replaces a symlink at name.
			defer er.close()
		}
	}
	// createFile replaces an existing entry and reports failures.
	return createFile(er.root, name)
}

// validPath reports what IsValidPath(target, dir) does.
func (er *entryRoots) validPath(target, dir string) bool {
	return pathWithin(target, dir, er.lstat)
}

// lstat examines path for the check IsValidPath makes, as lstatPath does. A
// path beneath the root is examined through the root on its directory: the
// root follows only symlinks that stay beneath it, and those lead where
// lstatPath's do, so a directory the root finds missing is missing for
// lstatPath too. The root itself is no symlink that leads outside itself.
// Any other path, or a directory the root cannot reach for another reason,
// is left to lstatPath.
func (er *entryRoots) lstat(path string) (fs.FileInfo, error) {
	rel, err := filepath.Rel(er.root.Name(), path)
	if err != nil || !filepath.IsLocal(rel) {
		return lstatPath(path)
	}
	r, base, release, err := er.dirs.Parent(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return lstatPath(path)
	}
	defer release()
	return r.Lstat(base)
}

// close closes the roots kept open. Later calls open them anew.
func (er *entryRoots) close() {
	er.dirs.Close()
}
