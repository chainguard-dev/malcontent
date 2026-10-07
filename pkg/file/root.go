// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// malcontent reaches every file through an os.Root on the directory that
// bounds it: the scan root, an archive's extraction directory, the rule
// cache, or, for a path a caller names directly, the directory that holds the
// file once symlinks are resolved. A root refuses names, and symlinks within
// them, that lead outside it.
//
// The functions ending in In open a root on dir for one operation on name,
// relative to it, and close it again; a file they return stays open. The
// functions named after their os counterparts take a caller-supplied path and
// reach it through a root on its resolved directory (see Split).

// inRoot runs op with an os.Root on dir.
func inRoot[T any](dir string, op func(*os.Root) (T, error)) (T, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		var zero T
		return zero, err
	}
	defer r.Close()
	return op(r)
}

// OpenIn opens name beneath dir for reading.
func OpenIn(dir, name string) (*os.File, error) {
	return inRoot(dir, func(r *os.Root) (*os.File, error) { return r.Open(name) })
}

// OpenFileIn opens name beneath dir with flag and, when it creates the file,
// perm.
func OpenFileIn(dir, name string, flag int, perm fs.FileMode) (*os.File, error) {
	return inRoot(dir, func(r *os.Root) (*os.File, error) { return r.OpenFile(name, flag, perm) })
}

// ReadFileIn returns the contents of name beneath dir.
func ReadFileIn(dir, name string) ([]byte, error) {
	return inRoot(dir, func(r *os.Root) ([]byte, error) { return r.ReadFile(name) })
}

// WriteFileIn writes data to name beneath dir, creating it with perm or
// truncating it.
func WriteFileIn(dir, name string, data []byte, perm fs.FileMode) error {
	_, err := inRoot(dir, func(r *os.Root) (struct{}, error) { return struct{}{}, r.WriteFile(name, data, perm) })
	return err
}

// StatIn returns the FileInfo of name beneath dir, following symlinks that
// stay beneath it.
func StatIn(dir, name string) (fs.FileInfo, error) {
	return inRoot(dir, func(r *os.Root) (fs.FileInfo, error) { return r.Stat(name) })
}

// LstatIn returns the FileInfo of name beneath dir without following a
// final symlink.
func LstatIn(dir, name string) (fs.FileInfo, error) {
	return inRoot(dir, func(r *os.Root) (fs.FileInfo, error) { return r.Lstat(name) })
}

// MkdirAllIn creates name beneath dir, and any missing parents, with perm.
func MkdirAllIn(dir, name string, perm fs.FileMode) error {
	_, err := inRoot(dir, func(r *os.Root) (struct{}, error) { return struct{}{}, r.MkdirAll(name, perm) })
	return err
}

// RemoveAllIn removes name beneath dir and everything it contains.
func RemoveAllIn(dir, name string) error {
	_, err := inRoot(dir, func(r *os.Root) (struct{}, error) { return struct{}{}, r.RemoveAll(name) })
	return err
}

// Split returns the directory that holds the file path names, with symlinks
// resolved, and the file's name in it: the root and name through which a
// caller-supplied path is reached. Resolving first keeps the meaning of a
// path that is itself a symlink to a file elsewhere. A path that does not
// exist yet, such as a file about to be created, is named in the resolved
// directory that will hold it.
func Split(path string) (string, string, error) {
	if path == "" {
		// os names no file by the empty path; a root on it would be the
		// working directory.
		return "", "", &fs.PathError{Op: "split", Path: path, Err: syscall.ENOENT}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return "", "", err
		}
		dir, derr := filepath.EvalSymlinks(filepath.Dir(path))
		if derr != nil {
			return "", "", err
		}
		resolved = filepath.Join(dir, filepath.Base(path))
	}
	dir, name := filepath.Split(resolved)
	if name == "" {
		// The filesystem root has no parent to hold it.
		return resolved, ".", nil
	}
	return filepath.Clean(dir), name, nil
}

// inPath runs op with an os.Root on the directory of the caller-supplied
// path and the file's name in it.
func inPath[T any](path string, op func(r *os.Root, name string) (T, error)) (T, error) {
	if r, name, ok := openParent(path); ok {
		defer r.Close()
		return op(r, name)
	}
	dir, name, err := splitPath(path)
	if err != nil {
		var zero T
		return zero, err
	}
	return inRoot(dir, func(r *os.Root) (T, error) { return op(r, name) })
}

// splitPath is Split. It is a variable so that tests can observe which paths
// need it.
var splitPath = Split

// openParent opens a root on the directory holding path, as the operating
// system resolves it, and returns it with the file's name in it, when that
// reaches the file Split would: path names a file by its last element, and
// the file is not itself a symlink, which a root follows only within its
// directory. It reports false otherwise, leaving path to Split, which
// resolves symlinks first at the cost of examining every element.
func openParent(path string) (*os.Root, string, bool) {
	dir, name := filepath.Split(path)
	if name == "" || name == "." {
		return nil, "", false
	}
	if dir == "" {
		dir = "."
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", false
	}
	fi, err := r.Lstat(name)
	if (err == nil && fi.Mode()&fs.ModeSymlink == 0) || errors.Is(err, fs.ErrNotExist) {
		return r, name, true
	}
	_ = r.Close()
	return nil, "", false
}

// Open opens the caller-supplied path for reading.
func Open(path string) (*os.File, error) {
	return inPath(path, func(r *os.Root, name string) (*os.File, error) { return r.Open(name) })
}

// OpenFile opens the caller-supplied path with flag and, when it creates the
// file, perm.
func OpenFile(path string, flag int, perm fs.FileMode) (*os.File, error) {
	return inPath(path, func(r *os.Root, name string) (*os.File, error) { return r.OpenFile(name, flag, perm) })
}

// ReadFile returns the contents of the caller-supplied path.
func ReadFile(path string) ([]byte, error) {
	return inPath(path, func(r *os.Root, name string) ([]byte, error) { return r.ReadFile(name) })
}

// Stat returns the FileInfo of the caller-supplied path.
func Stat(path string) (fs.FileInfo, error) {
	return inPath(path, func(r *os.Root, name string) (fs.FileInfo, error) { return r.Stat(name) })
}

// MkdirAll creates the caller-supplied directory path, and any missing
// parents, with perm, through a root on its deepest existing ancestor.
func MkdirAll(path string, perm fs.FileMode) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var rest []string
	for base := abs; ; base = filepath.Dir(base) {
		r, err := os.OpenRoot(base)
		if err == nil {
			if len(rest) > 0 {
				err = r.MkdirAll(filepath.Join(rest...), perm)
			}
			_ = r.Close()
			return err
		}
		if !errors.Is(err, fs.ErrNotExist) || filepath.Dir(base) == base {
			return err
		}
		rest = append([]string{filepath.Base(base)}, rest...)
	}
}

// CreateTemp creates a new file in r, opened for reading and writing with
// mode 0o600, and returns it with its name in r. The name is pattern with its
// last "*" replaced by a random string, or with one appended when pattern has
// none, as os.CreateTemp names files.
func CreateTemp(r *os.Root, pattern string) (*os.File, string, error) {
	if strings.ContainsRune(pattern, filepath.Separator) {
		return nil, "", &fs.PathError{Op: "createtemp", Path: pattern, Err: errors.New("pattern contains path separator")}
	}
	prefix, suffix, _ := strings.CutLast(pattern, "*")
	for range 10000 {
		name := prefix + strconv.FormatUint(uint64(rand.Uint32()), 10) + suffix // #nosec G404 -- uniqueness, not secrecy; O_EXCL guards collisions
		f, err := r.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, name, err
	}
	return nil, "", &fs.PathError{Op: "createtemp", Path: pattern, Err: fs.ErrExist}
}

// WalkDir walks the tree rooted at name beneath r as fs.WalkDir walks
// r.FS(): in lexical order, calling fn with slash-separated paths, without
// following symlinks below name, and with the same handling of errors,
// fs.SkipDir, and fs.SkipAll. It opens each directory relative to its parent
// rather than from r, so a directory costs one lookup however deep it lies.
func WalkDir(r *os.Root, name string, fn fs.WalkDirFunc) error {
	info, err := r.Stat(name)
	if err != nil {
		err = fn(name, nil, err)
	} else {
		err = walkEntry(r, name, name, fs.FileInfoToDirEntry(info), fn)
	}
	if errors.Is(err, fs.SkipDir) || errors.Is(err, fs.SkipAll) {
		return nil
	}
	return err
}

// walkEntry walks the entry d, at path, opened by elem beneath parent.
func walkEntry(parent *os.Root, elem, path string, d fs.DirEntry, fn fs.WalkDirFunc) error {
	if err := fn(path, d, nil); err != nil || !d.IsDir() {
		if errors.Is(err, fs.SkipDir) && d.IsDir() {
			err = nil
		}
		return err
	}

	dir, err := parent.OpenRoot(elem)
	var entries []fs.DirEntry
	if err == nil {
		defer dir.Close()
		entries, err = ReadDir(dir)
	}
	if err != nil {
		if err := fn(path, d, err); err != nil {
			if errors.Is(err, fs.SkipDir) && d.IsDir() {
				err = nil
			}
			return err
		}
	}
	for _, e := range entries {
		if err := walkEntry(dir, e.Name(), joinSlash(path, e.Name()), e, fn); err != nil {
			if errors.Is(err, fs.SkipDir) {
				break
			}
			return err
		}
	}
	return nil
}

// ReadDir returns the entries of the directory r is on, sorted by name, as
// fs.ReadDir does.
func ReadDir(r *os.Root) ([]fs.DirEntry, error) {
	f, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, err
}

// joinSlash joins a slash-separated directory path and a name as fs.WalkDir
// does.
func joinSlash(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}
