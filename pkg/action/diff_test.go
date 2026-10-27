// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// relPath returns the key of fr in a scan of from, and the base of its report
// key, through the scan root a diff computes once per side.
func relPath(from string, fr *malcontent.FileReport, isArchive bool) (string, string, error) {
	root, err := newScanRoot(from, isArchive)
	if err != nil {
		return "", "", err
	}
	rel, err := root.rel(fr)
	if err != nil {
		return "", "", err
	}
	return rel, root.base, nil
}

// TestRelPath tests the relPath function which computes relative paths for diff operations.
func TestRelPath(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	root := scanTestOpenRoot(t, tmpDir)

	// Create test file structure
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := root.WriteFile("test.txt", []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create archive directory structure
	archiveDir := filepath.Join(tmpDir, "archive")
	if err := root.MkdirAll("archive", 0o755); err != nil {
		t.Fatalf("failed to create archive dir: %v", err)
	}
	archiveFile := filepath.Join(archiveDir, "file")
	if err := root.WriteFile(filepath.Join("archive", "file"), []byte("archive content"), 0o644); err != nil {
		t.Fatalf("failed to create archive file: %v", err)
	}

	tests := []struct {
		name      string
		from      string
		fr        *malcontent.FileReport
		isArchive bool
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
			wantErr:   false,
			checkPath: false,
		},
		{
			name: "path with archive separator",
			from: testFile,
			fr: &malcontent.FileReport{
				Path:     testFile + " ∴ /bin/app",
				FullPath: testFile,
			},
			isArchive: false,
			wantErr:   false,
			checkPath: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rel, base, err := relPath(tt.from, tt.fr, tt.isArchive)
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
		{
			name:  "upx -k replaces the last character of a name with an extension",
			path:  "/opt/trino.linux-amd64.launche~",
			files: map[string]*malcontent.FileReport{"/opt/trino.linux-amd64.launcher": {}},
			want:  true,
		},
		{
			name:  "upx -k replaces a one-character extension",
			path:  "/bin/a.~",
			files: map[string]*malcontent.FileReport{"/bin/a.b": {}},
			want:  true,
		},
		{
			name:  "upx -k appends a tilde to a name ending in a dot",
			path:  "/bin/app.~",
			files: map[string]*malcontent.FileReport{"/bin/app.": {}},
			want:  true,
		},
		{
			name:  "archive entry backup pairs with its entry",
			path:  "linux/trino.launcher ∴ /trino.launche~",
			files: map[string]*malcontent.FileReport{"linux/trino.launcher ∴ /trino.launcher": {}},
			want:  true,
		},
		{
			name:  "replaced extension without the original file",
			path:  "/opt/trino.linux-amd64.launche~",
			files: map[string]*malcontent.FileReport{"/opt/trino.linux-amd64.launch": {}},
			want:  false,
		},
		{
			name:  "editor backup that appends a tilde to a name with an extension",
			path:  "/etc/notes.txt~",
			files: map[string]*malcontent.FileReport{"/etc/notes.txt": {}},
			want:  false,
		},
		{
			name:  "name ending in a tilde is not a backup of itself",
			path:  "/etc/notes.tx~",
			files: map[string]*malcontent.FileReport{"/etc/notes.tx~": {}},
			want:  false,
		},
		{
			name:  "extension only in a directory name",
			path:  "/etc.d/app~",
			files: map[string]*malcontent.FileReport{"/etc.d/apq": {}},
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
		{
			name: "upx -k backup of a name with an extension",
			files: map[string]*malcontent.FileReport{
				"/trino.linux-amd64.launche~": {Path: "/trino.linux-amd64.launche~"},
				"/trino.linux-amd64.launcher": {Path: "/trino.linux-amd64.launcher"},
			},
			want: "/trino.linux-amd64.launcher",
		},
		{
			// The tilde sorts before the last byte of the original name.
			name: "upx -k backup that sorts before its original",
			files: map[string]*malcontent.FileReport{
				"/app.ex\xc3~":    {Path: "/app.ex\xc3~"},
				"/app.ex\xc3\xa9": {Path: "/app.ex\xc3\xa9"},
			},
			want: "/app.ex\xc3\xa9",
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
			name: "with tmpRoot falls through to plain path",
			res:  ScanResult{tmpRoot: "/tmp/extract", imageURI: ""},
			file: "/tmp/extract/bin/ls",
			want: "/tmp/extract/bin/ls",
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
