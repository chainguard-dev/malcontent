// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// rootTestDir returns a temporary directory with symlinks resolved, as Split
// reports directories.
func rootTestDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return dir
}

// rootTestSymlink creates name in dir as a symlink to target.
func rootTestSymlink(t *testing.T, dir, target, name string) {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer r.Close()
	if err := r.Symlink(target, name); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
}

func TestInHelpers(t *testing.T) {
	t.Parallel()
	dir := rootTestDir(t)
	if err := MkdirAllIn(dir, filepath.Join("a", "b"), 0o700); err != nil {
		t.Fatalf("MkdirAllIn: %v", err)
	}
	name := filepath.Join("a", "b", "f.txt")
	if err := WriteFileIn(dir, name, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFileIn: %v", err)
	}
	if got, err := ReadFileIn(dir, name); err != nil || string(got) != "hello" {
		t.Errorf("ReadFileIn: got = (%q, %v), want = (%q, nil)", got, err, "hello")
	}
	f, err := OpenIn(dir, name)
	if err != nil {
		t.Fatalf("OpenIn: %v", err)
	}
	got, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(got) != "hello" {
		t.Errorf("OpenIn contents: got = (%q, %v), want = (%q, nil)", got, err, "hello")
	}
	w, err := OpenFileIn(dir, name, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("OpenFileIn: %v", err)
	}
	_, err = w.WriteString(" world")
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if fi, err := StatIn(dir, name); err != nil || fi.Size() != int64(len("hello world")) {
		t.Errorf("StatIn: got = (%v, %v), want a size of %d", fi, err, len("hello world"))
	}
	rootTestSymlink(t, dir, "f.txt", filepath.Join("a", "b", "link"))
	if fi, err := LstatIn(dir, filepath.Join("a", "b", "link")); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("LstatIn: got = (%v, %v), want the symlink itself", fi, err)
	}
	if err := RemoveAllIn(dir, "a"); err != nil {
		t.Fatalf("RemoveAllIn: %v", err)
	}
	if _, err := StatIn(dir, "a"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("StatIn after RemoveAllIn: got err = %v, want = %v", err, fs.ErrNotExist)
	}
}

func TestInHelpersStayInsideTheirDirectory(t *testing.T) {
	t.Parallel()
	outside := rootTestDir(t)
	if err := WriteFileIn(outside, "secret", []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFileIn: %v", err)
	}
	dir := rootTestDir(t)
	rootTestSymlink(t, dir, filepath.Join(outside, "secret"), "link")
	rootTestSymlink(t, dir, outside, "dirlink")
	tests := []struct {
		name string
		op   func() error
	}{
		{name: "parent reference", op: func() error {
			_, err := ReadFileIn(dir, filepath.Join("..", filepath.Base(outside), "secret"))
			return err
		}},
		{name: "symlink to a file outside", op: func() error { _, err := OpenIn(dir, "link"); return err }},
		{name: "symlinked directory outside", op: func() error { _, err := StatIn(dir, filepath.Join("dirlink", "secret")); return err }},
		{name: "write through a symlinked directory", op: func() error {
			return WriteFileIn(dir, filepath.Join("dirlink", "planted"), []byte("x"), 0o600)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.op(); err == nil {
				t.Error("operation: got err = nil, want it refused")
			}
		})
	}
	if _, err := StatIn(outside, "planted"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("file planted outside: got err = %v, want = %v", err, fs.ErrNotExist)
	}
}

func TestSplit(t *testing.T) {
	t.Parallel()
	dir := rootTestDir(t)
	other := rootTestDir(t)
	if err := WriteFileIn(other, "target", []byte("t"), 0o600); err != nil {
		t.Fatalf("WriteFileIn: %v", err)
	}
	if err := WriteFileIn(dir, "plain", []byte("p"), 0o600); err != nil {
		t.Fatalf("WriteFileIn: %v", err)
	}
	rootTestSymlink(t, dir, filepath.Join(other, "target"), "link")
	rootTestSymlink(t, dir, other, "dirlink")
	tests := []struct {
		name     string
		path     string
		wantDir  string
		wantName string
		wantErr  bool
	}{
		{name: "file", path: filepath.Join(dir, "plain"), wantDir: dir, wantName: "plain"},
		{name: "symlink to a file elsewhere", path: filepath.Join(dir, "link"), wantDir: other, wantName: "target"},
		{name: "file to be created", path: filepath.Join(dir, "new"), wantDir: dir, wantName: "new"},
		{name: "file to be created through a symlinked directory", path: filepath.Join(dir, "dirlink", "new"), wantDir: other, wantName: "new"},
		{name: "filesystem root", path: string(filepath.Separator), wantDir: string(filepath.Separator), wantName: "."},
		{name: "missing directory", path: filepath.Join(dir, "missing", "new"), wantErr: true},
		{name: "empty path", path: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotDir, gotName, err := Split(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Split(%q) error: got = %v, want error = %v", tt.path, err, tt.wantErr)
			}
			if gotDir != tt.wantDir || gotName != tt.wantName {
				t.Errorf("Split(%q): got = (%q, %q), want = (%q, %q)", tt.path, gotDir, gotName, tt.wantDir, tt.wantName)
			}
		})
	}
}

func TestPathHelpers(t *testing.T) {
	t.Parallel()
	dir := rootTestDir(t)
	other := rootTestDir(t)
	if err := WriteFileIn(other, "target", []byte("target"), 0o600); err != nil {
		t.Fatalf("WriteFileIn: %v", err)
	}
	link := filepath.Join(dir, "link")
	rootTestSymlink(t, dir, filepath.Join(other, "target"), "link")

	if got, err := ReadFile(link); err != nil || string(got) != "target" {
		t.Errorf("ReadFile through a symlink: got = (%q, %v), want = (%q, nil)", got, err, "target")
	}
	if fi, err := Stat(link); err != nil || fi.Size() != int64(len("target")) {
		t.Errorf("Stat through a symlink: got = (%v, %v), want the target's size", fi, err)
	}
	f, err := Open(link)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = f.Close()
	out, err := OpenFile(filepath.Join(dir, "out"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	_, err = out.WriteString("out")
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, err := ReadFileIn(dir, "out"); err != nil || string(got) != "out" {
		t.Errorf("file OpenFile created: got = (%q, %v), want = (%q, nil)", got, err, "out")
	}
	if _, err := ReadFile(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile of a missing file: got err = %v, want = %v", err, fs.ErrNotExist)
	}
	if _, err := Stat(""); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat of the empty path: got err = %v, want = %v", err, fs.ErrNotExist)
	}
}

func TestPathHelpersResolveAsTheSystemDoes(t *testing.T) {
	t.Parallel()
	base := rootTestDir(t)
	for name, body := range map[string]string{
		filepath.Join("a", "b", "file"): "a-b-file",
		filepath.Join("a", "sibling"):   "a-sibling",
		filepath.Join("dir", "sibling"): "dir-sibling",
	} {
		if err := MkdirAllIn(base, filepath.Dir(name), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := WriteFileIn(base, name, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	rootTestSymlink(t, filepath.Join(base, "dir"), filepath.Join(base, "a", "b"), "link")
	rootTestSymlink(t, filepath.Join(base, "dir"), filepath.Join("..", "a", "sibling"), "filelink")

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr error
	}{
		{name: "through a symlinked directory", path: filepath.Join(base, "dir", "link", "file"), want: "a-b-file"},
		// The symlink is followed before "..", which leads beside its target.
		{name: "parent of a symlinked directory", path: filepath.Join(base, "dir", "link") + "/../sibling", want: "a-sibling"},
		{name: "symlink to a file in another directory", path: filepath.Join(base, "dir", "filelink"), want: "a-sibling"},
		{name: "missing file", path: filepath.Join(base, "dir", "link", "missing"), wantErr: fs.ErrNotExist},
		{name: "file named as a directory", path: filepath.Join(base, "dir", "sibling") + "/", wantErr: syscall.ENOTDIR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ReadFile(tt.path)
			if string(got) != tt.want || !errors.Is(err, tt.wantErr) {
				t.Errorf("ReadFile(%q): got = (%q, %v), want = (%q, %v)", tt.path, got, err, tt.want, tt.wantErr)
			}
			fi, err := Stat(tt.path)
			if !errors.Is(err, tt.wantErr) || (err == nil && fi.Size() != int64(len(tt.want))) {
				t.Errorf("Stat(%q): got = (%v, %v), want size %d and err %v", tt.path, fi, err, len(tt.want), tt.wantErr)
			}
		})
	}

	created := filepath.Join(base, "dir", "link", "new")
	f, err := OpenFile(created, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("OpenFile(%q, O_CREATE): %v", created, err)
	}
	_ = f.Close()
	if _, err := StatIn(filepath.Join(base, "a", "b"), "new"); err != nil {
		t.Errorf("file created through a symlinked directory: got err = %v, want it beside its target", err)
	}
}

func TestMkdirAll(t *testing.T) {
	t.Parallel()
	dir := rootTestDir(t)
	if err := WriteFileIn(dir, "file", nil, 0o600); err != nil {
		t.Fatalf("WriteFileIn: %v", err)
	}
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "missing parents are created", path: filepath.Join(dir, "a", "b", "c")},
		{name: "one missing directory is created", path: filepath.Join(dir, "one")},
		{name: "existing directory", path: dir},
		{name: "beneath a regular file", path: filepath.Join(dir, "file", "sub"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := MkdirAll(tt.path, 0o700)
			if (err != nil) != tt.wantErr {
				t.Fatalf("MkdirAll(%q): got err = %v, want error = %v", tt.path, err, tt.wantErr)
			}
			if tt.wantErr {
				// The path that cannot be a directory is reported as given.
				var pe *fs.PathError
				if !errors.As(err, &pe) || pe.Path != tt.path || !errors.Is(err, syscall.ENOTDIR) {
					t.Errorf("MkdirAll(%q) error: got = %v, want %v for the path", tt.path, err, syscall.ENOTDIR)
				}
				return
			}
			if fi, err := Stat(tt.path); err != nil || !fi.IsDir() {
				t.Errorf("Stat(%q): got = (%v, %v), want a directory", tt.path, fi, err)
			}
		})
	}
}

func TestCreateTemp(t *testing.T) {
	t.Parallel()
	r, err := os.OpenRoot(rootTestDir(t))
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	// The subtests run after this function returns.
	t.Cleanup(func() { _ = r.Close() })
	tests := []struct {
		name, pattern, prefix, suffix string
		wantErr                       bool
	}{
		{name: "star is replaced", pattern: ".rules-*.tmp", prefix: ".rules-", suffix: ".tmp"},
		{name: "last star is replaced", pattern: "a*b*c", prefix: "a*b", suffix: "c"},
		{name: "random string is appended without a star", pattern: "plain", prefix: "plain"},
		{name: "path separator is refused", pattern: "a" + string(filepath.Separator) + "*", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f, name, err := CreateTemp(r, tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CreateTemp(%q): got err = %v, want error = %v", tt.pattern, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			defer f.Close()
			mid := strings.TrimSuffix(strings.TrimPrefix(name, tt.prefix), tt.suffix)
			if !strings.HasPrefix(name, tt.prefix) || !strings.HasSuffix(name, tt.suffix) || mid == "" || strings.Trim(mid, "0123456789") != "" {
				t.Errorf("name: got = %q, want %q, random digits, then %q", name, tt.prefix, tt.suffix)
			}
			fi, err := r.Stat(name)
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("created file: got = (%v, %v), want mode 0600", fi, err)
			}
			g, other, err := CreateTemp(r, tt.pattern)
			if err != nil {
				t.Fatalf("second CreateTemp: %v", err)
			}
			_ = g.Close()
			if other == name {
				t.Errorf("second name: got = %q again, want a new name", other)
			}
		})
	}
}

func TestWalkDirMatchesFSWalkDir(t *testing.T) {
	t.Parallel()
	dir := rootTestDir(t)
	for _, name := range []string{"b/z.txt", "b/a/deep/x.txt", "a.txt", "c/skip/hidden.txt", "c/kept.txt", "c/zzz.txt", "d/one.txt", "d/two.txt"} {
		if err := MkdirAllIn(dir, filepath.Dir(name), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := WriteFileIn(dir, name, []byte(name), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	rootTestSymlink(t, dir, "b", "link")
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	// visits records each call, ending the walk where fn says to.
	visits := func(walk func(fs.WalkDirFunc) error, fn func(path string, d fs.DirEntry) error) ([]string, error) {
		var got []string
		err := walk(func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				got = append(got, path+" error")
				return err
			}
			got = append(got, fmt.Sprintf("%s %v", path, d.Type()))
			return fn(path, d)
		})
		return got, err
	}
	tests := []struct {
		name  string
		start string
		fn    func(path string, d fs.DirEntry) error
	}{
		{name: "whole tree", start: ".", fn: func(string, fs.DirEntry) error { return nil }},
		{name: "subtree", start: "b", fn: func(string, fs.DirEntry) error { return nil }},
		{name: "single file", start: "a.txt", fn: func(string, fs.DirEntry) error { return nil }},
		{name: "missing start", start: "missing", fn: func(string, fs.DirEntry) error { return nil }},
		{name: "skip a directory", start: ".", fn: func(path string, _ fs.DirEntry) error {
			if path == "c/skip" {
				return fs.SkipDir
			}
			return nil
		}},
		{name: "skip the start", start: ".", fn: func(string, fs.DirEntry) error { return fs.SkipDir }},
		{name: "skip from a single file", start: "a.txt", fn: func(string, fs.DirEntry) error { return fs.SkipDir }},
		{name: "skip the rest of a directory from a file", start: ".", fn: func(path string, _ fs.DirEntry) error {
			if path == "d/one.txt" {
				return fs.SkipDir
			}
			return nil
		}},
		{name: "stop the walk", start: ".", fn: func(path string, _ fs.DirEntry) error {
			if path == "b/a" {
				return fs.SkipAll
			}
			return nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			want, wantErr := visits(func(fn fs.WalkDirFunc) error { return fs.WalkDir(r.FS(), tt.start, fn) }, tt.fn)
			got, err := visits(func(fn fs.WalkDirFunc) error { return WalkDir(r, tt.start, fn) }, tt.fn)
			if (err == nil) != (wantErr == nil) {
				t.Errorf("error: got = %v, want = %v", err, wantErr)
			}
			if !slices.Equal(got, want) {
				t.Errorf("visits:\ngot  = %q\nwant = %q", got, want)
			}
		})
	}
}

func TestWalkDirReportsUnreadableDirectories(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	dir := rootTestDir(t)
	if err := MkdirAllIn(dir, filepath.Join("locked", "sub"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	// Cleanups run last first: permissions are restored before the root
	// closes, so the temporary directory can be removed.
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Chmod("locked", 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = r.Chmod("locked", 0o700) })

	var errored []string
	err = WalkDir(r, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			errored = append(errored, path)
		}
		return nil
	})
	if err != nil || !slices.Equal(errored, []string{"locked"}) {
		t.Errorf("walk: got = (%q, %v), want an error reported for %q only", errored, err, "locked")
	}

	// What fn returns for the error decides the rest of the walk, as with
	// fs.WalkDir: skipping goes on with the directories after it, and any
	// other error ends the walk.
	if err := MkdirAllIn(dir, "zlater", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	errStop := errors.New("stop")
	for _, onErr := range []error{fs.SkipDir, errStop} {
		visits := func(walk func(fs.WalkDirFunc) error) ([]string, error) {
			var got []string
			err := walk(func(path string, _ fs.DirEntry, err error) error {
				got = append(got, fmt.Sprintf("%s %v", path, err != nil))
				if err != nil {
					return onErr
				}
				return nil
			})
			return got, err
		}
		want, wantErr := visits(func(fn fs.WalkDirFunc) error { return fs.WalkDir(r.FS(), ".", fn) })
		got, err := visits(func(fn fs.WalkDirFunc) error { return WalkDir(r, ".", fn) })
		if !errors.Is(err, wantErr) || (err == nil) != (wantErr == nil) || !slices.Equal(got, want) {
			t.Errorf("walk returning %v on errors: got = (%q, %v), want = (%q, %v)", onErr, got, err, want, wantErr)
		}
	}
}

func TestReadDirReportsUnreadableDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	r, err := os.OpenRoot(rootTestDir(t))
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Chmod(".", 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = r.Chmod(".", 0o700) })
	if entries, err := ReadDir(r); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("ReadDir: got = (%v, %v), want = %v", entries, err, fs.ErrPermission)
	}
}

// TestPathHelpersResolveSymlinksOnlyWhenNeeded replaces splitPath and changes
// the working directory, so it does not run in parallel.
func TestPathHelpersResolveSymlinksOnlyWhenNeeded(t *testing.T) {
	dir := rootTestDir(t)
	if err := WriteFileIn(dir, "file", []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFileIn: %v", err)
	}
	rootTestSymlink(t, dir, "file", "link")
	t.Chdir(dir)
	var resolved []string
	saved := splitPath
	splitPath = func(path string) (string, string, error) {
		resolved = append(resolved, path)
		return saved(path)
	}
	t.Cleanup(func() { splitPath = saved })

	tests := []struct {
		path        string
		wantResolve bool
	}{
		{path: filepath.Join(dir, "file")},
		{path: filepath.Join(dir, "missing")},
		{path: "file"},
		{path: filepath.Join(dir, "link"), wantResolve: true},
		{path: filepath.Join(dir, "missing", "file"), wantResolve: true},
		{path: dir + string(filepath.Separator), wantResolve: true},
		{path: dir + string(filepath.Separator) + ".", wantResolve: true},
		{path: "", wantResolve: true},
	}
	for _, tt := range tests {
		resolved = nil
		_, _ = Stat(tt.path)
		if got := len(resolved) > 0; got != tt.wantResolve {
			t.Errorf("Stat(%q) resolved symlinks first: got = %v, want = %v", tt.path, got, tt.wantResolve)
		}
	}
}
