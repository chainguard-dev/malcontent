// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestSymlinkExtraction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		tarFile string
		wantErr bool
	}{
		{
			// Relative symlink that escapes the extraction directory should be rejected
			name:    "relative symlink escaping directory is rejected",
			tarFile: "testdata/symlink_escape.tar",
			wantErr: true,
		},
		{
			name:    "valid symlink within directory",
			tarFile: "testdata/symlink_valid.tar",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tmpDir, err := os.MkdirTemp("", "symlink-test-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			ctx := context.Background()
			err = ExtractTar(ctx, tmpDir, tt.tarFile)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateResolvedPath(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("", "validate-resolved-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a subdirectory and a file inside the temp dir
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("test"), 0o600); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// A normal file path within the extraction dir should pass
	target := filepath.Join(subDir, "file.txt")
	if err := ValidateResolvedPath(target, tmpDir, "subdir/file.txt"); err != nil {
		t.Errorf("expected no error for valid path, got: %v", err)
	}

	// Create a symlink that points outside the extraction directory
	escapingLink := filepath.Join(tmpDir, "escape")
	if err := os.Symlink("/tmp", escapingLink); err != nil {
		t.Fatalf("failed to create escaping symlink: %v", err)
	}

	// A path whose parent resolves outside the dir should fail
	targetViaEscape := filepath.Join(escapingLink, "somefile")
	if err := ValidateResolvedPath(targetViaEscape, tmpDir, "escape/somefile"); err == nil {
		t.Error("expected error for path traversal via symlink, got nil")
	}

	// Create a symlink that points to a directory within the extraction dir
	internalLink := filepath.Join(tmpDir, "internal_link")
	if err := os.Symlink(subDir, internalLink); err != nil {
		t.Fatalf("failed to create internal symlink: %v", err)
	}

	// A path whose parent resolves within the dir should pass
	targetViaInternal := filepath.Join(internalLink, "file.txt")
	if err := ValidateResolvedPath(targetViaInternal, tmpDir, "internal_link/file.txt"); err != nil {
		t.Errorf("expected no error for valid symlink path, got: %v", err)
	}

	// A path with a nonexistent parent should pass (EvalSymlinks fails, returns nil)
	nonexistent := filepath.Join(tmpDir, "nonexistent", "file.txt")
	if err := ValidateResolvedPath(nonexistent, tmpDir, "nonexistent/file.txt"); err != nil {
		t.Errorf("expected no error for nonexistent parent, got: %v", err)
	}
}

// TestExtractNestedArchiveWithSubdirectory verifies that extractNestedArchive
// handles archives located in subdirectories (where the relative path contains
// path separators). This is a regression test for a bug where os.MkdirTemp
// was called with a pattern containing path separators, which is not allowed.
func TestExtractNestedArchiveWithSubdirectory(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("", "nested-archive-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a nested archive inside a subdirectory, simulating what happens
	// when an archive contains another archive at a path like "subdir/inner.tar.gz"
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// Copy a real .gz test file into the subdirectory
	srcData, err := os.ReadFile("../../pkg/action/testdata/apko.gz")
	if err != nil {
		t.Fatalf("failed to read test archive: %v", err)
	}
	nestedArchive := filepath.Join(subDir, "apko.gz")
	if err := os.WriteFile(nestedArchive, srcData, 0o600); err != nil {
		t.Fatalf("failed to write nested archive: %v", err)
	}

	ctx := context.Background()
	logger := clog.FromContext(ctx)
	cfg := malcontent.Config{}
	var extracted sync.Map

	// This is the call that previously failed with "pattern contains path separator"
	err = extractNestedArchive(ctx, cfg, tmpDir, "subdir/apko.gz", &extracted, logger, 1)
	if err != nil {
		t.Fatalf("extractNestedArchive failed: %v", err)
	}
}

// TestExtractNestedArchiveCollision verifies that extractNestedArchive handles
// name collisions by falling back to os.MkdirTemp when the deterministic path
// already exists.
func TestExtractNestedArchiveCollision(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("", "nested-collision-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a file that will collide with the extraction directory name.
	// When extracting "apko.gz", the extraction dir would be "apko" — create
	// that as a file first to force the collision path.
	collisionPath := filepath.Join(tmpDir, "apko")
	if err := os.WriteFile(collisionPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("failed to create collision file: %v", err)
	}

	srcData, err := os.ReadFile("../../pkg/action/testdata/apko.gz")
	if err != nil {
		t.Fatalf("failed to read test archive: %v", err)
	}
	archivePath := filepath.Join(tmpDir, "apko.gz")
	if err := os.WriteFile(archivePath, srcData, 0o600); err != nil {
		t.Fatalf("failed to write archive: %v", err)
	}

	ctx := context.Background()
	logger := clog.FromContext(ctx)
	cfg := malcontent.Config{}
	var extracted sync.Map

	err = extractNestedArchive(ctx, cfg, tmpDir, "apko.gz", &extracted, logger, 1)
	if err != nil {
		t.Fatalf("extractNestedArchive with collision failed: %v", err)
	}
}

// TestDanglingSymlinkExtraction verifies that a tar containing a dangling symlink
// (target doesn't exist) extracts without error and all extracted paths pass IsValidPath.
func TestDanglingSymlinkExtraction(t *testing.T) {
	t.Parallel()

	// Build a tar in memory with a dangling symlink (points to nonexistent file within dir)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "link",
		Typeflag: tar.TypeSymlink,
		Linkname: "nonexistent",
	}); err != nil {
		t.Fatal(err)
	}
	tw.Close()

	tmpFile, err := os.CreateTemp("", "dangling-symlink-*.tar")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(buf.Bytes())
	tmpFile.Close()

	tmpDir, err := os.MkdirTemp("", "dangling-symlink-extract-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Extraction should succeed
	if err := ExtractTar(context.Background(), tmpDir, tmpFile.Name()); err != nil {
		t.Fatalf("ExtractTar failed on dangling symlink: %v", err)
	}

	// Every extracted path must pass IsValidPath (this is what the fuzzer checks)
	err = filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !IsValidPath(path, tmpDir) {
			t.Errorf("IsValidPath returned false for dangling symlink: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}
}

func TestHandleSymlink(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("", "symlink-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// A symlink location which escapes should be rejected
	err = handleSymlink(tmpDir, "../escape", "target")
	if err == nil {
		t.Error("expected error for symlink location escaping directory")
	}

	// Absolute symlink targets are skipped (no error, no symlink created)
	err = handleSymlink(tmpDir, "abs_link", "/some/absolute/target")
	if err != nil {
		t.Errorf("unexpected error for absolute symlink target: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(tmpDir, "abs_link")); err == nil {
		t.Error("absolute symlink should not have been created")
	}

	// A relative symlink target which escapes should be rejected
	err = handleSymlink(tmpDir, "escape_link", "../../etc/passwd")
	if err == nil {
		t.Error("expected error for relative symlink target escaping directory")
	}

	// Write a file we can create a valid symlink for
	targetFile := filepath.Join(tmpDir, "realfile.txt")
	if err := os.WriteFile(targetFile, []byte("test"), 0o600); err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}

	// A valid relative symlink should succeed
	err = handleSymlink(tmpDir, "valid_link", "realfile.txt")
	if err != nil {
		t.Errorf("unexpected error for valid symlink: %v", err)
	}
	linkPath := filepath.Join(tmpDir, "valid_link")
	if _, err := os.Lstat(linkPath); err != nil {
		t.Errorf("valid symlink was not created: %v", err)
	}
}
