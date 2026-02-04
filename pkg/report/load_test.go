// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		wantErr         bool
		wantNonNilFiles bool // Only check FileReports != nil for these
	}{
		{
			name:            "valid empty report",
			data:            []byte(`{"Files":{}}`),
			wantErr:         false,
			wantNonNilFiles: true,
		},
		{
			name: "valid report with files",
			data: []byte(`{
				"Files": {
					"/bin/ls": {
						"Path": "/bin/ls",
						"RiskScore": 1,
						"RiskLevel": "low"
					}
				}
			}`),
			wantErr:         false,
			wantNonNilFiles: true,
		},
		{
			name:    "invalid json",
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte(``),
			wantErr: true,
		},
		{
			name:            "null",
			data:            []byte(`null`),
			wantErr:         false,
			wantNonNilFiles: false,
		},
		{
			name:            "empty object",
			data:            []byte(`{}`),
			wantErr:         false,
			wantNonNilFiles: false,
		},
		{
			name: "report with behaviors",
			data: []byte(`{
				"Files": {
					"/usr/bin/curl": {
						"Path": "/usr/bin/curl",
						"RiskScore": 2,
						"RiskLevel": "medium",
						"Behaviors": [
							{
								"ID": "net/http",
								"Description": "Makes HTTP requests"
							}
						]
					}
				}
			}`),
			wantErr:         false,
			wantNonNilFiles: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.wantNonNilFiles && got.FileReports == nil {
				t.Error("Load() returned report with nil FileReports map")
			}
		})
	}
}

func TestExtractImageURI(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]*malcontent.FileReport
		want  string
	}{
		{
			name:  "empty files",
			files: map[string]*malcontent.FileReport{},
			want:  "",
		},
		{
			name: "no image URI",
			files: map[string]*malcontent.FileReport{
				"/bin/ls": {Path: "/bin/ls"},
			},
			want: "",
		},
		{
			name: "with image URI",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "cgr.dev/chainguard/nginx:latest ∴ /usr/bin/nginx"},
			},
			want: "cgr.dev/chainguard/nginx:latest",
		},
		{
			name: "multiple files first with URI",
			files: map[string]*malcontent.FileReport{
				"key1": {Path: "ghcr.io/org/image:v1 ∴ /app/main"},
				"key2": {Path: "/bin/sh"},
			},
			want: "ghcr.io/org/image:v1",
		},
		{
			name: "path with ∴ but starts with slash",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "/tmp/extract ∴ /file"},
			},
			want: "",
		},
		{
			name: "nil file report",
			files: map[string]*malcontent.FileReport{
				"key": nil,
			},
			want: "",
		},
		{
			name: "empty path",
			files: map[string]*malcontent.FileReport{
				"key": {Path: ""},
			},
			want: "",
		},
		{
			name: "image URI with spaces",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "  registry.io/image:tag  ∴ /bin/file"},
			},
			want: "registry.io/image:tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractImageURI(tt.files)
			if got != tt.want {
				t.Errorf("ExtractImageURI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractTmpRoot(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]*malcontent.FileReport
		want  string
	}{
		{
			name:  "empty files",
			files: map[string]*malcontent.FileReport{},
			want:  "",
		},
		{
			name: "no temp paths",
			files: map[string]*malcontent.FileReport{
				"/bin/ls": {Path: "/bin/ls"},
			},
			want: "",
		},
		{
			name: "with /tmp/ path",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "/tmp/abc123/xyz789/T/extract/file"},
			},
			want: "/tmp/abc123/xyz789/T/extract",
		},
		{
			name: "with /var/folders/ path (macOS)",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "/var/folders/ab/cd123456/T/extract123/file.txt"},
			},
			want: "/var/folders/ab/cd123456/T/extract123",
		},
		{
			name: "with /private/var/folders/ path",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "/private/var/folders/xy/z9876543/T/temp_dir/file"},
			},
			want: "/private/var/folders/xy/z9876543/T/temp_dir",
		},
		{
			name: "with /private/tmp/ path",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "/private/tmp/abc/def/T/ghi/file"},
			},
			want: "/private/tmp/abc/def/T/ghi",
		},
		{
			name: "nil file report",
			files: map[string]*malcontent.FileReport{
				"key": nil,
			},
			want: "",
		},
		{
			name: "empty path",
			files: map[string]*malcontent.FileReport{
				"key": {Path: ""},
			},
			want: "",
		},
		{
			name: "multiple files returns one match",
			files: map[string]*malcontent.FileReport{
				"key1": {Path: "/tmp/aaa/bbb/T/ccc/file1"},
				"key2": {Path: "/tmp/xxx/yyy/T/zzz/file2"},
			},
			want: "", // map iteration order is non-deterministic, will check separately
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractTmpRoot(tt.files)

			// edge case: multiple files test (map iteration is non-deterministic)
			if tt.name == "multiple files returns one match" {
				validResults := []string{"/tmp/aaa/bbb/T/ccc", "/tmp/xxx/yyy/T/zzz"}
				isValid := slices.Contains(validResults, got)
				if !isValid {
					t.Errorf("ExtractTmpRoot() = %q, want one of %v", got, validResults)
				}
				return
			}

			if got != tt.want {
				t.Errorf("ExtractTmpRoot() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCleanReportPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		tmpRoot  string
		imageURI string
		want     string
	}{
		{
			name:     "empty path",
			path:     "",
			tmpRoot:  "",
			imageURI: "",
			want:     "",
		},
		{
			name:     "path already has image URI",
			path:     "cgr.dev/image:tag ∴ /bin/file",
			tmpRoot:  "/tmp/extract",
			imageURI: "cgr.dev/image:tag",
			want:     "cgr.dev/image:tag ∴ /bin/file",
		},
		{
			name:     "remove tmp root",
			path:     "/tmp/abc123/xyz/T/extract/bin/ls",
			tmpRoot:  "/tmp/abc123/xyz/T/extract",
			imageURI: "",
			want:     "/bin/ls",
		},
		{
			name:     "path without tmp root",
			path:     "/usr/bin/curl",
			tmpRoot:  "/tmp/extract",
			imageURI: "",
			want:     "/usr/bin/curl",
		},
		{
			name:     "relative path gets leading slash",
			path:     "bin/file",
			tmpRoot:  "",
			imageURI: "",
			want:     "/bin/file",
		},
		{
			name:     "path with temp pattern",
			path:     "/var/folders/ab/cd/T/extract/file",
			tmpRoot:  "",
			imageURI: "",
			want:     "/file",
		},
		{
			name:     "already clean absolute path",
			path:     "/bin/sh",
			tmpRoot:  "",
			imageURI: "",
			want:     "/bin/sh",
		},
		{
			name:     "image URI prefix preserved",
			path:     "registry.io/image ∴ /app/main",
			tmpRoot:  "",
			imageURI: "registry.io/image",
			want:     "registry.io/image ∴ /app/main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanReportPath(tt.path, tt.tmpRoot, tt.imageURI)
			if got != tt.want {
				t.Errorf("CleanReportPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatReportKey(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		tmpRoot  string
		imageURI string
		want     string
	}{
		{
			name:     "empty path",
			path:     "",
			tmpRoot:  "",
			imageURI: "",
			want:     "",
		},
		{
			name:     "path with image URI prefix",
			path:     "cgr.dev/image:tag ∴ /bin/file",
			tmpRoot:  "",
			imageURI: "cgr.dev/image:tag",
			want:     "cgr.dev/image:tag ∴ /bin/file",
		},
		{
			name:     "format with image URI",
			path:     "/tmp/extract/bin/ls",
			tmpRoot:  "/tmp/extract",
			imageURI: "registry.io/image:v1",
			want:     "registry.io/image:v1 ∴ /bin/ls",
		},
		{
			name:     "format without image URI",
			path:     "/tmp/extract/usr/bin/curl",
			tmpRoot:  "/tmp/extract",
			imageURI: "",
			want:     "/usr/bin/curl",
		},
		{
			name:     "clean path without tmp root",
			path:     "/bin/sh",
			tmpRoot:  "",
			imageURI: "",
			want:     "/bin/sh",
		},
		{
			name:     "relative path gets leading slash",
			path:     "app/main",
			tmpRoot:  "",
			imageURI: "",
			want:     "/app/main",
		},
		{
			name:     "path with temp pattern",
			path:     "/var/folders/ab/cd/T/xyz/file.txt",
			tmpRoot:  "",
			imageURI: "",
			want:     "/file.txt",
		},
		{
			name:     "path with temp pattern and image URI",
			path:     "/private/tmp/a/b/T/c/bin/app",
			tmpRoot:  "",
			imageURI: "ghcr.io/org/app:latest",
			want:     "ghcr.io/org/app:latest ∴ /bin/app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatReportKey(tt.path, tt.tmpRoot, tt.imageURI)
			if got != tt.want {
				t.Errorf("FormatReportKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadRoundTrip(t *testing.T) {
	original := malcontent.ScanResult{
		FileReports: map[string]*malcontent.FileReport{
			"/bin/ls": {
				Path:      "/bin/ls",
				RiskScore: 1,
				RiskLevel: "low",
			},
			"/usr/bin/curl": {
				Path:      "/usr/bin/curl",
				RiskScore: 2,
				RiskLevel: "medium",
			},
		},
	}

	// marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// load the JSON data
	loaded, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// verify contents
	if len(loaded.FileReports) != len(original.FileReports) {
		t.Errorf("loaded %d files, want %d", len(loaded.FileReports), len(original.FileReports))
	}

	for key, origFR := range original.FileReports {
		loadedFR, ok := loaded.FileReports[key]
		if !ok {
			t.Errorf("missing file %q in loaded report", key)
			continue
		}

		if loadedFR.Path != origFR.Path {
			t.Errorf("file %q: path = %q, want %q", key, loadedFR.Path, origFR.Path)
		}

		if loadedFR.RiskScore != origFR.RiskScore {
			t.Errorf("file %q: risk score = %d, want %d", key, loadedFR.RiskScore, origFR.RiskScore)
		}

		if loadedFR.RiskLevel != origFR.RiskLevel {
			t.Errorf("file %q: risk level = %q, want %q", key, loadedFR.RiskLevel, origFR.RiskLevel)
		}
	}
}
