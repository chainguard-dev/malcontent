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
			// Symlinks pointing outside the directory are allowed
			// (common in container images, e.g., /etc/mtab -> /proc/mounts)
			name:    "symlink target outside directory is allowed",
			tarFile: "testdata/symlink_escape.tar",
			wantErr: false,
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
	tmpDir, err := os.MkdirTemp("", "symlink-location-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Symlink location that would escape should be rejected
	err = handleSymlink(tmpDir, "../escape", "target")
	if err == nil {
		t.Error("expected error for symlink location escaping directory")
	}

	// Valid symlink location should succeed
	err = handleSymlink(tmpDir, "valid_link", "/some/absolute/target")
	if err != nil {
		t.Errorf("unexpected error for valid symlink location: %v", err)
	}

	// Verify symlink was created
	linkPath := filepath.Join(tmpDir, "valid_link")
	if _, err := os.Lstat(linkPath); err != nil {
		t.Errorf("symlink was not created: %v", err)
	}
}
