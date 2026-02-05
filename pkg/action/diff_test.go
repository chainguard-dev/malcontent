// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// TestRelPath tests the relPath function which computes relative paths for diff operations.
func TestRelPath(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Create test file structure
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create archive directory structure
	archiveDir := filepath.Join(tmpDir, "archive")
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatalf("failed to create archive dir: %v", err)
	}
	archiveFile := filepath.Join(archiveDir, "file")
	if err := os.WriteFile(archiveFile, []byte("archive content"), 0o644); err != nil {
		t.Fatalf("failed to create archive file: %v", err)
	}

	tests := []struct {
		name      string
		from      string
		fr        *malcontent.FileReport
		isArchive bool
		isImage   bool
		wantErr   bool
		checkPath bool
	}{
		{
			name: "safe relative path",
			from: tmpDir,
			fr: &malcontent.FileReport{
				Path:     filepath.Join(tmpDir, "safe.txt"),
				FullPath: filepath.Join(tmpDir, "safe.txt"),
			},
			isArchive: false,
			isImage:   false,
			wantErr:   false,
			checkPath: true,
		},
		{
			name: "path with .. components",
			from: tmpDir,
			fr: &malcontent.FileReport{
				Path:     filepath.Join(tmpDir, "..", "etc", "passwd"),
				FullPath: filepath.Join(tmpDir, "..", "etc", "passwd"),
			},
			isArchive: false,
			isImage:   false,
			wantErr:   false, // relPath computes paths, validation is done by archive.IsValidPath
			checkPath: true,
		},
		{
			name: "absolute path escape",
			from: tmpDir,
			fr: &malcontent.FileReport{
				Path:     "/etc/passwd",
				FullPath: "/etc/passwd",
			},
			isArchive: false,
			isImage:   false,
			wantErr:   false,
			checkPath: true,
		},
		{
			name: "archive path",
			from: "",
			fr: &malcontent.FileReport{
				Path:        "image:tag ∴ /safe/file",
				FullPath:    archiveFile,
				ArchiveRoot: archiveDir,
			},
			isArchive: true,
			isImage:   false,
			wantErr:   false,
			checkPath: false,
		},
		{
			name: "image path with separator",
			from: testFile,
			fr: &malcontent.FileReport{
				Path:     testFile + " ∴ /bin/app",
				FullPath: testFile,
			},
			isArchive: false,
			isImage:   true,
			wantErr:   false,
			checkPath: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base, rel, err := relPath(tt.from, tt.fr, tt.isArchive, tt.isImage)
			if (err != nil) != tt.wantErr {
				t.Errorf("relPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && tt.checkPath {
				t.Logf("base=%q rel=%q", base, rel)
			}
		})
	}
}

func TestIsUPXBackup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		path  string
		files map[string]*malcontent.FileReport
		want  bool
	}{
		{
			name:  "upx backup with decompressed file",
			path:  "/path/to/file.~",
			files: map[string]*malcontent.FileReport{"/path/to/file": {}},
			want:  true,
		},
		{
			name:  "upx backup without decompressed file",
			path:  "/path/to/file.~",
			files: map[string]*malcontent.FileReport{},
			want:  false,
		},
		{
			name:  "normal file",
			path:  "/path/to/file",
			files: map[string]*malcontent.FileReport{},
			want:  false,
		},
		{
			name:  "empty path",
			path:  "",
			files: map[string]*malcontent.FileReport{},
			want:  false,
		},
		{
			name:  "tilde without dot is not upx backup",
			path:  "/path/to/file~",
			files: map[string]*malcontent.FileReport{"/path/to/file": {}},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isUPXBackup(tt.path, tt.files)
			if got != tt.want {
				t.Errorf("isUPXBackup(%q, ...) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestSelectPrimaryFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files map[string]*malcontent.FileReport
		want  string // expected path of selected file
	}{
		{
			name:  "empty map",
			files: map[string]*malcontent.FileReport{},
			want:  "",
		},
		{
			name: "single file",
			files: map[string]*malcontent.FileReport{
				"/file": {Path: "/file"},
			},
			want: "/file",
		},
		{
			name: "backup and decompressed - prefer decompressed",
			files: map[string]*malcontent.FileReport{
				"/file~": {Path: "/file~"},
				"/file":  {Path: "/file"},
			},
			want: "/file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := selectPrimaryFile(tt.files)
			if got == nil && tt.want == "" {
				return // both nil, OK
			}
			if got == nil || got.Path != tt.want {
				gotPath := ""
				if got != nil {
					gotPath = got.Path
				}
				t.Errorf("selectPrimaryFile() = %v, want path %v", gotPath, tt.want)
			}
		})
	}
}

func TestFormatKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		res  ScanResult
		file string
		want string
	}{
		{
			name: "simple path no context",
			res:  ScanResult{tmpRoot: "", imageURI: ""},
			file: "/bin/ls",
			want: "/bin/ls",
		},
		{
			name: "with tmpRoot prepends tmpRoot",
			res:  ScanResult{tmpRoot: "/tmp/extract", imageURI: ""},
			file: "/tmp/extract/bin/ls",
			want: "/tmp/extract ∴ /tmp/extract/bin/ls",
		},
		{
			name: "with image URI prepends imageURI",
			res:  ScanResult{tmpRoot: "/tmp/extract", imageURI: "registry.io/image:v1"},
			file: "/tmp/extract/app/main",
			want: "registry.io/image:v1 ∴ /tmp/extract/app/main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatKey(tt.res, tt.file)
			if got != tt.want {
				t.Errorf("formatKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
