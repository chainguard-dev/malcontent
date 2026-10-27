// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// maxIdleEntryRoots bounds the directory roots an extraction keeps open while
// no entry uses them.
const maxIdleEntryRoots = 1024

// entryRoots reaches the directories one extraction writes entries to
// through roots kept open from entry to entry, so that creating a file or a
// directory is one lookup in its parent rather than one per element of its
// path. Creating a link can change where names beneath it lead, so the
// extraction closes the roots after doing so.
type entryRoots struct {
	root *os.Root
	dirs *file.DirRoots
}

func newEntryRoots(root *os.Root) *entryRoots {
	return &entryRoots{root: root, dirs: file.NewDirRoots(root, maxIdleEntryRoots)}
}

// openExclusive creates name, which must not exist, beneath the root for
// writing, creating its parent directories when they are missing.
func (er *entryRoots) openExclusive(name string) (*os.File, error) {
	out, err := er.openExclusiveIn(name)
	if errors.Is(err, fs.ErrNotExist) {
		if err := er.root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return nil, err
		}
		out, err = er.openExclusiveIn(name)
	}
	return out, err
}

func (er *entryRoots) openExclusiveIn(name string) (*os.File, error) {
	r, base, release, err := er.dirs.Parent(name)
	if err != nil {
		return nil, err
	}
	defer release()
	return r.OpenFile(base, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// mkdir creates the directory name, whose parent exists, beneath the root.
func (er *entryRoots) mkdir(name string) error {
	r, base, release, err := er.dirs.Parent(name)
	if err != nil {
		return err
	}
	defer release()
	return r.Mkdir(base, 0o700)
}

// close closes the roots kept open. Later calls open them anew.
func (er *entryRoots) close() {
	er.dirs.Close()
}
