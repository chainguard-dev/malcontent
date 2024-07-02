package action

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanPath(t *testing.T) {
	// create a temporary directory
	tempDir, err := os.MkdirTemp("", "TestCleanPath")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// create and symlink a nested directory
	// create a file within the nested directory
	nestedDir := filepath.Join(tempDir, "nested")
	if err := os.Mkdir(nestedDir, 0o755); err != nil {
		t.Fatalf("failed to create nested directory: %v", err)
	}
	symlinkPath := filepath.Join(tempDir, "symlink")
	if err := os.Symlink(nestedDir, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	filePath := filepath.Join(nestedDir, "test.txt")
	file, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer file.Close()

	tests := []struct {
		name    string
		path    string
		prefix  string
		want    string
		wantErr bool
	}{
		{
			name:   "expected behavior",
			path:   filepath.Join(nestedDir, "test.txt"),
			prefix: nestedDir,
			want:   "/test.txt",
		},
		{
			name:   "symlink in path",
			path:   filepath.Join(symlinkPath, "test.txt"),
			prefix: nestedDir,
			want:   "/test.txt",
		},
		{
			name:   "symlink in prefix",
			path:   filepath.Join(nestedDir, "test.txt"),
			prefix: symlinkPath,
			want:   "/test.txt",
		},
		{
			name:    "non-existent path",
			path:    filepath.Join(tempDir, "does_not_exist", "test.txt"),
			prefix:  tempDir,
			wantErr: true,
		},
		{
			name:   "path prefix mismatch",
			path:   filepath.Join(nestedDir, "test.txt"),
			prefix: "",
			want:   filepath.Join(nestedDir, "test.txt"),
		},
		{
			name:   "empty paths",
			path:   "",
			prefix: "",
			want:   "",
		},
		{
			name:   "identical path and prefix",
			path:   nestedDir,
			prefix: nestedDir,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cleanPath(tt.path, tt.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("cleanPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !strings.HasSuffix(got, tt.want) {
				t.Errorf("cleanPath() = %v, want suffix %v", got, tt.want)
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
			name: "single separator",
			path: "/apko_0.13.2_linux_arm64/apko",
			want: "apko_0.13.2_linux_arm64/apko",
		},
		{
			name: "multiple separators",
			path: "/usr/share/zoneinfo/zone1970",
			want: "usr/share/zoneinfo/zone1970",
		},
		{
			name: "multiple windows separators",
			path: "\\usr\\share\\zoneinfo\\zone1970",
			want: "usr/share/zoneinfo/zone1970",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatPath(tt.path); got != tt.want {
				t.Errorf("FormatPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
