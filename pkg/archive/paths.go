// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

// caseInsensitiveFS reports whether the extraction filesystem may fold case,
// as macOS volumes do by default. There, entries such as META-INF/LICENSE and
// META-INF/license/ name the same path, so entryPaths folds names before
// comparing them. It is a var so tests can enable the handling on any
// platform.
var caseInsensitiveFS = runtime.GOOS == "darwin"

// maxCollisionNames bounds the sibling names tried for one entry.
const maxCollisionNames = 1024

// unnamedEntry names a file entry whose name leaves nothing once cleaned,
// such as "" or "/".
const unnamedEntry = "unnamed"

// maxElementBytes is the longest element entryName leaves in a path: below
// the 255 bytes the filesystems extraction writes to accept, leaving room for
// the suffix of a sibling name.
const maxElementBytes = 240

// entryName returns the path, relative to the extraction root, that an entry
// named name is written to, and whether it differs from the name as the
// archive gives it. A name is cut at its first NUL byte, as Python's zipfile
// cuts it, a leading "/" is dropped, and ".." elements that would climb above
// the root are dropped, so that the entry is extracted beneath the root
// rather than skipped. An element that merely contains dots, such as "v1..",
// is kept. An element too long for the filesystem is shortened. The root
// itself is ".".
func entryName(name string) (string, bool) {
	raw := name
	if i := strings.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	clean := strings.TrimPrefix(filepath.Clean("/"+name), "/")
	if clean == "" {
		clean = "."
	}
	changed := raw != name || filepath.Clean(name) != clean
	if len(clean) > maxElementBytes {
		elems := strings.Split(clean, string(filepath.Separator))
		for i, elem := range elems {
			elems[i] = shortenElement(elem)
		}
		if short := filepath.Join(elems...); short != clean {
			clean, changed = short, true
		}
	}
	return clean, changed
}

// shortenElement returns elem, or, when it is longer than maxElementBytes, its
// leading bytes followed by "~", the first 16 hex digits of its SHA-256
// digest, and its extension, so that distinct long names stay distinct and
// keep the extension their kind is recognized by.
func shortenElement(elem string) string {
	if len(elem) <= maxElementBytes {
		return elem
	}
	sum := sha256.Sum256([]byte(elem))
	ext := programkind.GetExt(elem)
	if len(ext) > 32 {
		ext = ""
	}
	tag := "~" + hex.EncodeToString(sum[:8]) + ext
	keep := maxElementBytes - len(tag)
	for keep > 0 && !utf8.RuneStart(elem[keep]) {
		keep--
	}
	return elem[:keep] + tag
}

// fileEntryName is entryName for an entry that is not a directory, which
// cannot be written at the root itself.
func fileEntryName(name string) (string, bool) {
	clean, changed := entryName(name)
	if clean == "." {
		return unnamedEntry, true
	}
	return clean, changed
}

// collisionNames yields name and then up to maxCollisionNames sibling names
// derived from it. Each suffix goes before the extension programkind reports,
// so a renamed nested archive is still recognized by its name.
func collisionNames(name string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if !yield(name) {
			return
		}
		dir, base := filepath.Split(name)
		ext := programkind.GetExt(base)
		if len(ext) >= len(base) || !strings.HasSuffix(base, ext) {
			ext = ""
		}
		stem := strings.TrimSuffix(base, ext)
		for i := range maxCollisionNames {
			if !yield(dir + stem + "_" + strconv.Itoa(i+1) + ext) {
				return
			}
		}
	}
}

// entryKind is what an extraction placed at a path.
type entryKind uint8

const (
	kindNone entryKind = iota
	kindDir
	kindFile
	kindLink
)

// entryPaths assigns every entry of one extraction the path it is written to
// beneath the extraction root, so that no entry replaces, or writes through,
// another. An entry whose path is taken gets a sibling name; a directory whose
// path holds anything other than a directory, or a symlink to one, gets a new
// sibling directory, which every entry beneath it then shares. On a
// filesystem that folds case, names are compared folded, so entries differing
// only in case stay apart too. The extraction directory starts empty and only
// this extraction writes to it, so assignments made in archive order are the
// same on every run; one the filesystem refuses all the same, as for a path
// reached through a symlink, moves on to the next sibling name. It is safe for
// concurrent use.
type entryPaths struct {
	er   *entryRoots
	fold bool

	mu sync.Mutex
	// taken maps each path this extraction placed something at, folded when
	// fold, to what it placed there.
	taken map[string]entryKind
	// dirs maps each directory as entries name it, folded when fold, to the
	// directory created for it.
	dirs map[string]string
	// files maps each other entry as entries name it, folded when fold, to
	// the path of the latest one, which hard links name.
	files map[string]string
}

func newEntryPaths(er *entryRoots) *entryPaths {
	return &entryPaths{
		er:    er,
		fold:  caseInsensitiveFS,
		taken: map[string]entryKind{},
		dirs:  map[string]string{},
		files: map[string]string{},
	}
}

func (p *entryPaths) key(name string) string {
	if p.fold {
		return strings.ToLower(name)
	}
	return name
}

// dir returns the directory created for name, a cleaned relative path,
// creating it and any missing parents.
func (p *entryPaths) dir(name string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dirLocked(name)
}

func (p *entryPaths) dirLocked(name string) (string, error) {
	if name == "." {
		return name, nil
	}
	if !filepath.IsLocal(name) {
		return "", fmt.Errorf("failed to create directory: path outside extraction directory: %q", name)
	}
	k := p.key(name)
	if got, ok := p.dirs[k]; ok {
		return got, nil
	}
	parent, err := p.dirLocked(filepath.Dir(name))
	if err != nil {
		return "", err
	}
	want := filepath.Join(parent, filepath.Base(name))
	for candidate := range collisionNames(want) {
		ok, err := p.claimDir(candidate, candidate == want)
		if err != nil {
			return "", err
		}
		if ok {
			p.dirs[k] = candidate
			return candidate, nil
		}
	}
	return "", fmt.Errorf("failed to create directory: no unused name derived from %q", want)
}

// claimDir reports whether candidate can hold a directory, creating one there
// when nothing does. Only the wanted name may be reused, and only when it is a
// directory, or a symlink that stays beneath the root and leads to one, so
// that entries beneath a symlinked directory land where the link leads, as
// GNU tar writes them. A sibling must be new, so renamed contents stay apart.
func (p *entryPaths) claimDir(candidate string, wanted bool) (bool, error) {
	k := p.key(candidate)
	switch p.taken[k] {
	case kindDir:
		return wanted, nil
	case kindFile:
		return false, nil
	case kindLink:
		return wanted && p.isDir(candidate), nil
	case kindNone:
	}
	err := p.er.mkdir(candidate)
	switch {
	case err == nil:
		p.taken[k] = kindDir
		return true, nil
	case errors.Is(err, fs.ErrExist):
		if wanted && p.isDir(candidate) {
			p.taken[k] = kindDir
			return true, nil
		}
		p.taken[k] = kindFile
		return false, nil
	default:
		return false, fmt.Errorf("failed to create directory: %w", err)
	}
}

// isDir reports whether name, followed through any symlink that stays beneath
// the root, is a directory.
func (p *entryPaths) isDir(name string) bool {
	fi, err := p.er.root.Stat(name)
	return err == nil && fi.IsDir()
}

// reserve assigns name, a cleaned relative path naming an entry of the given
// kind, the first path derived from it that this extraction has not taken,
// and records it as taken.
func (p *entryPaths) reserve(name string, kind entryKind) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	parent, err := p.dirLocked(filepath.Dir(name))
	if err != nil {
		return "", err
	}
	want := filepath.Join(parent, filepath.Base(name))
	for candidate := range collisionNames(want) {
		k := p.key(candidate)
		if p.taken[k] != kindNone {
			continue
		}
		p.taken[k] = kind
		p.files[p.key(name)] = candidate
		return candidate, nil
	}
	return "", fmt.Errorf("no unused name derived from %q", want)
}

// forget releases a path reserve assigned when nothing was written there.
func (p *entryPaths) forget(name, assigned string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.taken, p.key(assigned))
	if p.files[p.key(name)] == assigned {
		delete(p.files, p.key(name))
	}
}

// lookup returns the path the latest entry named name was written to, or name
// itself when no entry of that name was written.
func (p *entryPaths) lookup(name string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if got, ok := p.files[p.key(name)]; ok {
		return got
	}
	if got, ok := p.dirs[p.key(name)]; ok {
		return got
	}
	return name
}

// createFile creates the file for name, a cleaned relative path, and returns
// it with the path it was created at.
func (p *entryPaths) createFile(name string) (*os.File, string, error) {
	assigned, err := p.reserve(name, kindFile)
	if err != nil {
		return nil, "", err
	}
	return p.createAt(name, assigned)
}

// createAt creates the file for name at assigned, a path reserve returned for
// it, or, when the filesystem holds something there that this extraction did
// not record, at the next free sibling name. Exclusive creation never follows
// a symlink and never truncates what another entry wrote.
func (p *entryPaths) createAt(name, assigned string) (*os.File, string, error) {
	for range maxCollisionNames {
		out, err := p.er.openExclusive(assigned)
		if err == nil {
			return out, assigned, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			p.forget(name, assigned)
			return nil, "", fmt.Errorf("failed to create file: %w", err)
		}
		if assigned, err = p.reserve(name, kindFile); err != nil {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("failed to create file: no unused name derived from %q", name)
}

// symlink creates a symlink for name, a cleaned relative path, to target, at
// a free path derived from name, as handleSymlink validates it.
func (p *entryPaths) symlink(name, target string) (string, error) {
	for range maxCollisionNames {
		assigned, err := p.reserve(name, kindLink)
		if err != nil {
			return "", err
		}
		err = handleSymlink(p.er.root, assigned, target)
		if err == nil {
			return assigned, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			p.forget(name, assigned)
			return "", err
		}
	}
	return "", fmt.Errorf("failed to create symlink: no unused name derived from %q", name)
}

// link creates name, a cleaned relative path, as a hard link to existing, a
// path this extraction wrote, at a free path derived from name. A link to a
// symlink is recreated as a symlink, whose target then resolves from its own
// location and is validated there. A target that does not exist, or is a
// directory, is reported as an error.
func (p *entryPaths) link(name, existing string) (string, error) {
	fi, err := p.er.root.Lstat(existing)
	if err != nil {
		return "", fmt.Errorf("hard link target %q: %w", existing, err)
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		target, err := p.er.root.Readlink(existing)
		if err != nil {
			return "", fmt.Errorf("failed to read hard link target: %w", err)
		}
		return p.symlink(name, target)
	case fi.IsDir():
		return "", fmt.Errorf("hard link target %q is a directory", existing)
	}
	for range maxCollisionNames {
		assigned, err := p.reserve(name, kindFile)
		if err != nil {
			return "", err
		}
		err = p.er.root.Link(existing, assigned)
		if errors.Is(err, fs.ErrNotExist) {
			if mkErr := p.er.root.MkdirAll(filepath.Dir(assigned), 0o700); mkErr != nil {
				p.forget(name, assigned)
				return "", fmt.Errorf("failed to create parent directory for hard link: %w", mkErr)
			}
			err = p.er.root.Link(existing, assigned)
		}
		if err == nil {
			return assigned, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			p.forget(name, assigned)
			return "", fmt.Errorf("failed to create hard link: %w", err)
		}
	}
	return "", fmt.Errorf("failed to create hard link: no unused name derived from %q", name)
}
