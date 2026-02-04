// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindFilesRecursively(t *testing.T) {
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

	for _, f := range files {
		fullPath := filepath.Join(tmpDir, f)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte("test"), 0o644); err != nil {
			t.Fatalf("failed to create file %s: %v", fullPath, err)
		}
	}

	// Create a .git directory that should be ignored
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatalf("failed to create .git directory: %v", err)
	}
	gitFile := filepath.Join(gitDir, "config")
	if err := os.WriteFile(gitFile, []byte("git config"), 0o644); err != nil {
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
			ctx := context.Background()
			got, err := findFilesRecursively(ctx, tt.rootPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("findFilesRecursively() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(got) != tt.wantCount {
				t.Errorf("findFilesRecursively() found %d files, want %d", len(got), tt.wantCount)
				t.Logf("Files found: %v", got)
			}

			// Verify no .git files are included
			for _, f := range got {
				if strings.Contains(f, "/.git/") {
					t.Errorf("findFilesRecursively() included .git file: %s", f)
				}
			}
		})
	}
}

func TestFindFilesRecursivelySymlinks(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file
	targetFile := filepath.Join(tmpDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("content"), 0o644); err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}

	// Create a symlink to the file
	symlinkFile := filepath.Join(tmpDir, "link.txt")
	if err := os.Symlink(targetFile, symlinkFile); err != nil {
		t.Skipf("failed to create symlink (may not be supported): %v", err)
	}

	ctx := context.Background()
	files, err := findFilesRecursively(ctx, tmpDir)
	if err != nil {
		t.Fatalf("findFilesRecursively() error = %v", err)
	}

	// Should find only the target file, not the symlink (L51-53 in path.go)
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d: %v", len(files), files)
	}
}

func TestFindFilesRecursivelySymlinkRoot(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a directory with a file
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("failed to create target directory: %v", err)
	}

	targetFile := filepath.Join(targetDir, "file.txt")
	if err := os.WriteFile(targetFile, []byte("content"), 0o644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create a symlink to the directory
	linkDir := filepath.Join(tmpDir, "link")
	if err := os.Symlink(targetDir, linkDir); err != nil {
		t.Skipf("failed to create symlink (may not be supported): %v", err)
	}

	ctx := context.Background()
	files, err := findFilesRecursively(ctx, linkDir)
	if err != nil {
		t.Fatalf("findFilesRecursively() error = %v", err)
	}

	// Should follow the symlink at the root and find the file
	if len(files) != 1 {
		t.Errorf("Expected 1 file through symlinked root, got %d: %v", len(files), files)
	}
}

func TestFindFilesRecursivelyCanceledContext(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := findFilesRecursively(ctx, tmpDir)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("findFilesRecursively() with canceled context error = %v, want %v", err, context.Canceled)
	}
}

func TestFindFilesRecursivelyPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping permission test when running as root")
	}

	tmpDir := t.TempDir()

	// Create a subdirectory
	restrictedDir := filepath.Join(tmpDir, "restricted")
	if err := os.MkdirAll(restrictedDir, 0o755); err != nil {
		t.Fatalf("failed to create restricted directory: %v", err)
	}

	// Create a file in the restricted directory
	restrictedFile := filepath.Join(restrictedDir, "secret.txt")
	if err := os.WriteFile(restrictedFile, []byte("secret"), 0o644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create a normal file
	normalFile := filepath.Join(tmpDir, "normal.txt")
	if err := os.WriteFile(normalFile, []byte("normal"), 0o644); err != nil {
		t.Fatalf("failed to create normal file: %v", err)
	}

	// Remove read permissions from restricted directory
	if err := os.Chmod(restrictedDir, 0o000); err != nil {
		t.Fatalf("failed to chmod directory: %v", err)
	}
	defer os.Chmod(restrictedDir, 0o755) // Restore permissions for cleanup

	ctx := context.Background()
	files, err := findFilesRecursively(ctx, tmpDir)
	// Should not return error, just skip restricted directory
	if err != nil {
		t.Errorf("findFilesRecursively() error = %v, expected to skip permission denied", err)
	}

	// Should find the normal file
	if len(files) < 1 {
		t.Error("findFilesRecursively() should find at least the normal file")
	}

	// Should not find the restricted file
	for _, f := range files {
		if strings.Contains(f, "secret.txt") {
			t.Error("findFilesRecursively() should not access permission-denied files")
		}
	}
}

func TestFindFilesRecursivelyEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	ctx := context.Background()
	files, err := findFilesRecursively(ctx, tmpDir)
	if err != nil {
		t.Fatalf("findFilesRecursively() error = %v", err)
	}

	if len(files) != 0 {
		t.Errorf("findFilesRecursively() on empty directory found %d files, want 0", len(files))
	}
}

func TestFindFilesRecursivelyDeepNesting(t *testing.T) {
	tmpDir := t.TempDir()

	// Create deeply nested structure
	deepPath := tmpDir
	for range 50 {
		deepPath = filepath.Join(deepPath, "level")
	}

	if err := os.MkdirAll(deepPath, 0o755); err != nil {
		t.Fatalf("failed to create deep directory: %v", err)
	}

	deepFile := filepath.Join(deepPath, "deep.txt")
	if err := os.WriteFile(deepFile, []byte("deep"), 0o644); err != nil {
		t.Fatalf("failed to create deep file: %v", err)
	}

	ctx := context.Background()
	files, err := findFilesRecursively(ctx, tmpDir)
	if err != nil {
		t.Fatalf("findFilesRecursively() error = %v", err)
	}

	if len(files) != 1 {
		t.Errorf("findFilesRecursively() found %d files in deep structure, want 1", len(files))
	}
}

func TestCleanPath(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanPath(tt.path, tt.prefix)
			if got != tt.want {
				t.Errorf("CleanPath(%q, %q) = %q, want %q", tt.path, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestFormatPath(t *testing.T) {
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
			got := formatPath(tt.path)
			if got != tt.want {
				t.Errorf("formatPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
