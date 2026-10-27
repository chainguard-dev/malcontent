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

// MaxDirectPath is the longest path malcontent hands the operating system, or
// a program it runs, whole. The operating system refuses paths past PATH_MAX:
// 1,024 bytes on macOS and 4,096 on Linux. A longer path is reached through a
// root on a prefix of it, or its file is staged at a short path. Below this
// length, the names that code adds to a path keep it short enough everywhere.
const MaxDirectPath = 512

// OpenRoot opens a root on dir, as os.OpenRoot does. A dir longer than the
// operating system accepts whole, past PATH_MAX, is opened through a root on
// a prefix it accepts, which resolves the rest of dir an element at a time.
// Symlinks in the rest are then followed only within that prefix.
func OpenRoot(dir string) (*os.Root, error) {
	r, err := os.OpenRoot(dir)
	if !errors.Is(err, syscall.ENAMETOOLONG) {
		return r, err
	}
	prefix, rest := splitLong(dir)
	pr, err := os.OpenRoot(prefix)
	if err != nil {
		return nil, err
	}
	defer pr.Close()
	return pr.OpenRoot(rest)
}

// splitLong splits dir, at a separator within its first MaxDirectPath bytes,
// into a prefix the operating system accepts whole and the rest of dir
// relative to it.
func splitLong(dir string) (string, string) {
	i := strings.LastIndexByte(dir[:min(len(dir), MaxDirectPath)], filepath.Separator)
	switch {
	case i > 0:
		return dir[:i], dir[i+1:]
	case i == 0:
		return dir[:1], dir[1:]
	default:
		return ".", dir
	}
}

// inRoot runs op with an os.Root on dir.
func inRoot[T any](dir string, op func(*os.Root) (T, error)) (T, error) {
	r, err := OpenRoot(dir)
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
	r, err := OpenRoot(dir)
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
		r, err := OpenRoot(base)
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
