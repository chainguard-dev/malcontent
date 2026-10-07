// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
)

// walkTestPaths returns the paths walkScanPath finds beneath rootPath.
func walkTestPaths(ctx context.Context, t *testing.T, rootPath string) ([]string, error) {
	t.Helper()
	w, files, err := walkScanPath(ctx, rootPath)
	w.close()
	if err != nil {
		return nil, err
	}
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.path
	}
	return paths, nil
}

func TestWalkScanPath(t *testing.T) {
	t.Parallel()
	// Create temporary test directory structure
	tmpDir := t.TempDir()

	// Create files and directories
	files := []string{
		"file1.txt",
		"file2.go",
		"subdir/file3.txt",
		"subdir/nested/file4.sh",
		"another/file5.py",
	}

	root, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("failed to open %s: %v", tmpDir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, f := range files {
		dir := filepath.Dir(f)
		if err := root.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("failed to create directory %s: %v", dir, err)
		}
		if err := root.WriteFile(f, []byte("test"), 0o644); err != nil {
			t.Fatalf("failed to create file %s: %v", f, err)
		}
	}

	// Create a .git directory that should be ignored
	if err := root.MkdirAll(".git", 0o755); err != nil {
		t.Fatalf("failed to create .git directory: %v", err)
	}
	if err := root.WriteFile(filepath.Join(".git", "config"), []byte("git config"), 0o644); err != nil {
		t.Fatalf("failed to create git file: %v", err)
	}

	tests := []struct {
		name      string
		rootPath  string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "scan all files",
			rootPath:  tmpDir,
			wantCount: len(files), // Should find all files but not .git files
			wantErr:   false,
		},
		{
			name:      "scan subdirectory",
			rootPath:  filepath.Join(tmpDir, "subdir"),
			wantCount: 2, // file3.txt and nested/file4.sh
			wantErr:   false,
		},
		{
			name:      "scan single file",
			rootPath:  filepath.Join(tmpDir, "file1.txt"),
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "non-existent path",
			rootPath:  filepath.Join(tmpDir, "nonexistent"),
			wantCount: 0,
			wantErr:   false, // Should return nil, nil for non-existent symlinks
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			got, err := walkTestPaths(ctx, t, tt.rootPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("walkScanPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(got) != tt.wantCount {
				t.Errorf("walkScanPath() found %d files, want %d", len(got), tt.wantCount)
				t.Logf("Files found: %v", got)
			}

			// Verify no .git files are included
			for _, f := range got {
				if strings.Contains(f, "/.git/") {
					t.Errorf("walkScanPath() included .git file: %s", f)
				}
			}
		})
	}
}

func TestWalkScanPathSymlinks(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	root, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("failed to open %s: %v", tmpDir, err)
	}
	defer root.Close()

	// Create a file
	if err := root.WriteFile("target.txt", []byte("content"), 0o644); err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}

	// Create a symlink to the file
	if err := root.Symlink(filepath.Join(tmpDir, "target.txt"), "link.txt"); err != nil {
		t.Skipf("failed to create symlink (may not be supported): %v", err)
	}

	ctx := t.Context()
	files, err := walkTestPaths(ctx, t, tmpDir)
	if err != nil {
		t.Fatalf("walkScanPath() error = %v", err)
	}

	// Should find only the target file, not the symlink (L51-53 in path.go)
	if len(files) != 1 {
		t.Errorf("files found: got = %d (%v), want = 1", len(files), files)
	}
}

func TestWalkScanPathSymlinkRoot(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	root, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("failed to open %s: %v", tmpDir, err)
	}
	defer root.Close()

	// Create a directory with a file
	if err := root.MkdirAll("target", 0o755); err != nil {
		t.Fatalf("failed to create target directory: %v", err)
	}

	if err := root.WriteFile(filepath.Join("target", "file.txt"), []byte("content"), 0o644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create a symlink to the directory
	linkDir := filepath.Join(tmpDir, "link")
	if err := root.Symlink(filepath.Join(tmpDir, "target"), "link"); err != nil {
		t.Skipf("failed to create symlink (may not be supported): %v", err)
	}

	ctx := t.Context()
	files, err := walkTestPaths(ctx, t, linkDir)
	if err != nil {
		t.Fatalf("walkScanPath() error = %v", err)
	}

	// Should follow the symlink at the root and find the file
	if len(files) != 1 {
		t.Errorf("files found through symlinked root: got = %d (%v), want = 1", len(files), files)
	}
}

func TestWalkScanPathCanceledContext(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Create a file
	if err := file.WriteFileIn(tmpDir, "test.txt", []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	_, err := walkTestPaths(ctx, t, tmpDir)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("walkScanPath() with canceled context error = %v, want %v", err, context.Canceled)
	}
}

func TestWalkScanPathPermissionDenied(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("Skipping permission test when running as root")
	}

	// Walks report paths with symlinks resolved.
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}

	root, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("failed to open %s: %v", tmpDir, err)
	}
	defer root.Close()

	// Create a subdirectory
	if err := root.MkdirAll("restricted", 0o755); err != nil {
		t.Fatalf("failed to create restricted directory: %v", err)
	}

	// Create a file in the restricted directory
	if err := root.WriteFile(filepath.Join("restricted", "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create a normal file
	if err := root.WriteFile("normal.txt", []byte("normal"), 0o644); err != nil {
		t.Fatalf("failed to create normal file: %v", err)
	}

	// A file after the restricted directory is still found.
	if err := root.WriteFile("zzz.txt", []byte("after"), 0o644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Remove read permissions from restricted directory
	if err := root.Chmod("restricted", 0o000); err != nil {
		t.Fatalf("failed to chmod directory: %v", err)
	}
	defer root.Chmod("restricted", 0o755) // Restore permissions for cleanup

	ctx, logs := walkTestLogs(t)
	files, err := walkTestPaths(ctx, t, tmpDir)
	// Should not return error, just skip restricted directory
	if err != nil {
		t.Errorf("walkScanPath() error = %v, expected to skip permission denied", err)
	}

	// Should find the normal file and the one after the restricted directory
	want := []string{filepath.Join(tmpDir, "normal.txt"), filepath.Join(tmpDir, "zzz.txt")}
	if !slices.Equal(files, want) {
		t.Errorf("walkScanPath() = %q, want %q", files, want)
	}
	if want := "error: " + filepath.Join(tmpDir, "restricted") + ":"; !strings.Contains(logs.String(), want) {
		t.Errorf("logs: got = %q, want them to contain %q", logs.String(), want)
	}

	// Should not find the restricted file
	for _, f := range files {
		if strings.Contains(f, "secret.txt") {
			t.Error("walkScanPath() should not access permission-denied files")
		}
	}
}

func TestWalkScanPathEmptyDirectory(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	ctx := t.Context()
	files, err := walkTestPaths(ctx, t, tmpDir)
	if err != nil {
		t.Fatalf("walkScanPath() error = %v", err)
	}

	if len(files) != 0 {
		t.Errorf("walkScanPath() on empty directory found %d files, want 0", len(files))
	}
}

func TestWalkScanPathDeepNesting(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Create deeply nested structure
	deepPath := "."
	for range 50 {
		deepPath = filepath.Join(deepPath, "level")
	}

	if err := file.MkdirAllIn(tmpDir, deepPath, 0o755); err != nil {
		t.Fatalf("failed to create deep directory: %v", err)
	}

	if err := file.WriteFileIn(tmpDir, filepath.Join(deepPath, "deep.txt"), []byte("deep"), 0o644); err != nil {
		t.Fatalf("failed to create deep file: %v", err)
	}

	ctx := t.Context()
	files, err := walkTestPaths(ctx, t, tmpDir)
	if err != nil {
		t.Fatalf("walkScanPath() error = %v", err)
	}

	if len(files) != 1 {
		t.Errorf("walkScanPath() found %d files in deep structure, want 1", len(files))
	}
}

// pathTestRepo creates a repository layout under dir: a source file, a .git
// directory with nested entries, and a nested repository's .git directory.
func pathTestRepo(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{
		"main.go",
		filepath.Join(".git", "config"),
		filepath.Join(".git", "objects", "ab", "cd"),
		filepath.Join("sub", ".git", "config"),
	} {
		scanTestWriteFile(t, filepath.Join(dir, name), []byte("x"))
	}
}

func TestWalkScanPathGitDirectories(t *testing.T) {
	t.Parallel()
	// Walks report paths below the root with symlinks resolved.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	repo := filepath.Join(base, "repo")
	pathTestRepo(t, repo)

	tests := []struct {
		name string
		root string
		want []string
	}{
		{name: "repository reports only files outside .git directories", root: repo, want: []string{filepath.Join(repo, "main.go")}},
		{name: "a .git directory as the root reports nothing", root: filepath.Join(repo, ".git")},
		{name: "a directory inside .git as the root reports nothing", root: filepath.Join(repo, ".git", "objects")},
		{name: "a file inside .git as the root reports nothing", root: filepath.Join(repo, ".git", "config")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := walkTestPaths(t.Context(), t, tt.root)
			if err != nil {
				t.Fatalf("walkScanPath: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("files: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestFindFilesRecursivelyRelativeGitDirectory covers walks from relative
// roots, whose top-level .git directory is named ".git" rather than
// ".../.git", so its entries are reported.
func TestWalkScanPathRelativeGitDirectory(t *testing.T) {
	// Not parallel: changes the working directory.
	dir := t.TempDir()
	pathTestRepo(t, dir)
	t.Chdir(dir)

	gitFiles := []string{filepath.Join(".git", "config"), filepath.Join(".git", "objects", "ab", "cd")}
	tests := []struct {
		name string
		root string
		want []string
	}{
		{name: "the working directory reports its top-level .git entries", root: ".", want: append(slices.Clone(gitFiles), "main.go")},
		{name: "a relative .git root reports its entries", root: ".git", want: gitFiles},
		{name: "a nested .git directory reports nothing", root: filepath.Join("sub", ".git")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := walkTestPaths(t.Context(), t, tt.root)
			if err != nil {
				t.Fatalf("walkScanPath: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("files: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestCleanPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		path   string
		prefix string
		want   string
	}{
		{
			name:   "remove prefix",
			path:   "/tmp/extract/bin/ls",
			prefix: "/tmp/extract",
			want:   "/bin/ls",
		},
		{
			name:   "no prefix match",
			path:   "/usr/bin/ls",
			prefix: "/tmp/extract",
			want:   "/usr/bin/ls",
		},
		{
			name:   "empty prefix",
			path:   "/usr/bin/ls",
			prefix: "",
			want:   "/usr/bin/ls",
		},
		{
			name:   "empty path",
			path:   "",
			prefix: "/tmp",
			want:   "",
		},
		{
			name:   "windows path",
			path:   "C:\\Users\\test\\file.txt",
			prefix: "",
			want:   "C:/Users/test/file.txt",
		},
		{
			name:   "partial prefix match - no strip",
			path:   "/tmp/extract2/bin/ls",
			prefix: "/tmp/extract",
			want:   "/tmp/extract2/bin/ls",
		},
		{
			name:   "windows prefix removed at a backslash boundary",
			path:   "C:\\tmp\\extract\\bin\\ls",
			prefix: "C:\\tmp\\extract",
			want:   "/bin/ls",
		},
		{
			name:   "windows partial prefix match is not stripped",
			path:   "C:\\tmp\\extract2\\bin\\ls",
			prefix: "C:\\tmp\\extract",
			want:   "C:/tmp/extract2/bin/ls",
		},
		{
			name:   "path equal to the prefix is emptied",
			path:   "/tmp/extract",
			prefix: "/tmp/extract",
			want:   "",
		},
		{
			name:   "relative path with an empty prefix",
			path:   "bin\\ls",
			prefix: "",
			want:   "bin/ls",
		},
		{
			name:   "empty path and prefix",
			path:   "",
			prefix: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CleanPath(tt.path, tt.prefix)
			if got != tt.want {
				t.Errorf("CleanPath(%q, %q) = %q, want %q", tt.path, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestFormatPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "unix path unchanged",
			path: "/usr/bin/ls",
			want: "/usr/bin/ls",
		},
		{
			name: "windows path converted",
			path: "C:\\Users\\test\\file.txt",
			want: "C:/Users/test/file.txt",
		},
		{
			name: "mixed separators",
			path: "/tmp\\test/file\\name.txt",
			want: "/tmp/test/file/name.txt",
		},
		{
			name: "empty path",
			path: "",
			want: "",
		},
		{
			name: "only backslashes",
			path: "\\\\\\",
			want: "///",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatPath(tt.path)
			if got != tt.want {
				t.Errorf("formatPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestWalkScanPathMatchesASequentialWalk(t *testing.T) {
	t.Parallel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()
	// Enough directories, at several depths, that many are read at once.
	for i := range 300 {
		name := filepath.Join(fmt.Sprintf("d%d", i%7), fmt.Sprintf("e%d", i%31), fmt.Sprintf("f%03d", i))
		if i%50 == 0 {
			name = filepath.Join(fmt.Sprintf("d%d", i%7), ".git", fmt.Sprintf("objects%d", i))
		}
		if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := root.WriteFile(name, make([]byte, i), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := root.Symlink("d1", "link"); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	type found struct {
		name    string
		size    int64
		regular bool
	}
	var want []found
	if err := fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && d.Name() == ".git":
			return fs.SkipDir
		case d.IsDir() || d.Type()&fs.ModeSymlink != 0:
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		want = append(want, found{name: filepath.FromSlash(name), size: fi.Size(), regular: d.Type().IsRegular()})
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}

	w, files, err := walkScanPath(t.Context(), dir)
	if err != nil {
		t.Fatalf("walkScanPath: %v", err)
	}
	defer w.close()
	got := make([]found, len(files))
	for i, f := range files {
		got[i] = found{name: f.name, size: f.size, regular: f.regular}
		if f.path != filepath.Join(dir, f.name) {
			t.Errorf("path of %s: got = %q, want = %q", f.name, f.path, filepath.Join(dir, f.name))
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("walk: got %d files = %v, want %d = %v", len(got), got, len(want), want)
	}
}

// walkTestLogs returns a context whose logger records debug messages in the
// returned buffer.
func walkTestLogs(t *testing.T) (context.Context, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	return clog.WithLogger(t.Context(), clog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))), &logs
}

func TestWalkScanPathUnreadableScanPath(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("root reads every directory")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err := root.MkdirAll("searchable", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := root.WriteFile(filepath.Join("searchable", "file"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Searchable but not readable: a root cannot open it.
	if err := root.Chmod("searchable", 0o300); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = root.Chmod("searchable", 0o700) })

	for _, path := range []string{filepath.Join(dir, "searchable"), filepath.Join(dir, "searchable", "file")} {
		ctx, logs := walkTestLogs(t)
		w, files, err := walkScanPath(ctx, path)
		w.close()
		if w != nil || files != nil || err != nil {
			t.Errorf("walkScanPath(%q): got = (%v, %v, %v), want nothing, as for any entry the walk cannot read", path, w, files, err)
		}
		if want := "error: " + path + ":"; !strings.Contains(logs.String(), want) {
			t.Errorf("logs of %q: got = %q, want them to contain %q", path, logs.String(), want)
		}
	}
}

func TestWalkScanPathDanglingSymlinkRoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()
	if err := root.Symlink("missing", "dangling"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	ctx, logs := walkTestLogs(t)
	w, files, err := walkScanPath(ctx, filepath.Join(dir, "dangling"))
	if w != nil || files != nil || err != nil {
		t.Errorf("walkScanPath: got = (%v, %v, %v), want nothing", w, files, err)
	}
	if !strings.Contains(logs.String(), "symlink target does not exist") {
		t.Errorf("logs: got = %q, want the missing target reported", logs.String())
	}
}

func TestWalkScanPathUnresolvableProcLink(t *testing.T) {
	t.Parallel()
	// Another user's process: its executable link cannot be read.
	path := "/proc/1/exe"
	if _, err := filepath.EvalSymlinks(path); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Skipf("%s resolves here or is missing (%v)", path, err)
	}
	w, files, err := walkScanPath(t.Context(), path)
	if w != nil || files != nil || err != nil {
		t.Errorf("walkScanPath(%q): got = (%v, %v, %v), want nothing", path, w, files, err)
	}
}
