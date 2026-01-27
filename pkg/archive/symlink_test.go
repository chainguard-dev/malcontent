package archive

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSymlinkExtraction(t *testing.T) {
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

func TestHandleSymlink(t *testing.T) {
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
	if err := os.WriteFile(targetFile, []byte("test"), 0o644); err != nil {
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
