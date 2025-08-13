package action

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"github.com/google/go-cmp/cmp"
)

func TestExtractionMethod(t *testing.T) {
	tests := []struct {
		name string
		ext  string
		want func(context.Context, string, string) error
	}{
		{"apk", ".apk", archive.ExtractTar},
		{"gem", ".gem", archive.ExtractTar},
		{"gzip", ".gz", archive.ExtractGzip},
		{"jar", ".jar", archive.ExtractZip},
		{"tar.gz", ".tar.gz", archive.ExtractTar},
		{"tar.xz", ".tar.xz", archive.ExtractTar},
		{"tar", ".tar", archive.ExtractTar},
		{"tgz", ".tgz", archive.ExtractTar},
		{"unknown", ".unknown", nil},
		{"upx", ".upx", nil},
		{"zip", ".zip", archive.ExtractZip},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := archive.ExtractionMethod(tt.ext)
			if (got == nil) != (tt.want == nil) {
				t.Errorf("extractionMethod() for extension %v did not return expected result", tt.ext)
			}
		})
	}
}

func TestExtractionMultiple(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{
			path: filepath.Join("testdata", "apko.tar.gz"),
			want: []string{
				"apko_0.13.2_linux_arm64",
			},
		}, {
			path: filepath.Join("testdata", "apko.gz"),
			want: []string{
				"apko",
			},
		}, {
			path: filepath.Join("testdata", "apko.zip"),
			want: []string{
				"apko_0.13.2_linux_arm64",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			dir, err := archive.ExtractArchiveToTempDir(ctx, malcontent.Config{}, tt.path)
			if err != nil {
				t.Fatal(err)
			}
			dirFiles, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(dirFiles) != len(tt.want) {
				t.Fatalf("unexpected number of files in dir: %d", len(dirFiles))
			}
			var got []string
			for _, f := range dirFiles {
				got = append(got, f.Name())
			}
			for i, f := range tt.want {
				if f != got[i] {
					t.Fatalf("file %q not found in dir", f)
				}
			}
		})
	}
}

func TestExtractTar(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir, err := archive.ExtractArchiveToTempDir(ctx, malcontent.Config{}, filepath.Join("testdata", "apko.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"apko_0.13.2_linux_arm64",
	}
	dirFiles, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dirFiles) != len(want) {
		t.Fatalf("unexpected number of files in dir: %d", len(dirFiles))
	}
	got := make([]string, 0, len(dirFiles))
	for _, f := range dirFiles {
		got = append(got, f.Name())
	}
	for i, f := range want {
		if f != got[i] {
			t.Fatalf("file %q not found in dir", f)
		}
	}
}

func TestExtractGzip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir, err := archive.ExtractArchiveToTempDir(ctx, malcontent.Config{}, filepath.Join("testdata", "apko.gz"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"apko",
	}
	dirFiles, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dirFiles) != len(want) {
		t.Fatalf("unexpected number of files in dir: %d", len(dirFiles))
	}
	got := make([]string, 0, len(dirFiles))
	for _, f := range dirFiles {
		got = append(got, f.Name())
	}
	for i, f := range want {
		if f != got[i] {
			t.Fatalf("file %q not found in dir", f)
		}
	}
}

func TestExtractZip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir, err := archive.ExtractArchiveToTempDir(ctx, malcontent.Config{}, filepath.Join("testdata", "apko.zip"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"apko_0.13.2_linux_arm64",
	}
	dirFiles, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dirFiles) != len(want) {
		t.Fatalf("unexpected number of files in dir: %d", len(dirFiles))
	}
	got := make([]string, 0, len(dirFiles))
	for _, f := range dirFiles {
		got = append(got, f.Name())
	}
	for i, f := range want {
		if f != got[i] {
			t.Fatalf("file %q not found in dir", f)
		}
	}
}

func TestExtractNestedArchive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir, err := archive.ExtractArchiveToTempDir(ctx, malcontent.Config{}, filepath.Join("testdata", "apko_nested.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"apko_0.13.2_linux_arm64",
	}
	dirFiles, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dirFiles) != len(want) {
		t.Fatalf("unexpected number of files in dir: %d", len(dirFiles))
	}
	got := make([]string, 0, len(dirFiles))
	for _, f := range dirFiles {
		got = append(got, f.Name())
	}
	for i, f := range want {
		if f != got[i] {
			t.Fatalf("file %q not found in dir", f)
		}
	}
}

func TestScanArchive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clog.FromContext(ctx).With("test", "scan_archive")

	var out bytes.Buffer
	r, err := render.New("json", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	mc := malcontent.Config{
		Concurrency: runtime.NumCPU(),
		IgnoreSelf:  false,
		MinFileRisk: 0,
		MinRisk:     0,
		Renderer:    r,
		Rules:       yrs,
		ScanPaths:   []string{"testdata/apko_nested.tar.gz"},
	}
	res, err := Scan(ctx, mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Full(ctx, nil, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	got := out.String()

	td, err := os.ReadFile("testdata/scan_archive")
	if err != nil {
		t.Fatalf("testdata read failed: %v", err)
	}
	want := string(td)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch: (-want +got):\n%s", diff)
	}
}

func extractError(e error) error {
	if strings.Contains(e.Error(), "not a valid gzip archive") || strings.Contains(e.Error(), "not a valid zip archive") {
		return nil
	}
	return e
}

func TestScanInvalidArchive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clog.FromContext(ctx).With("test", "scan_invalid_archive")

	var out bytes.Buffer
	r, err := render.New("json", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	mc := malcontent.Config{
		Concurrency:    runtime.NumCPU(),
		ExitExtraction: true,
		IgnoreSelf:     false,
		MinFileRisk:    0,
		MinRisk:        0,
		Renderer:       r,
		Rules:          yrs,
		ScanPaths: []string{
			"testdata/17419.zip",
			"testdata/joblib_0.9.4.dev0_compressed_cache_size_pickle_py35_np19.gz",
		},
	}
	_, err = Scan(ctx, mc)
	err = extractError(err)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanInvalidArchiveIgnore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clog.FromContext(ctx).With("test", "scan_invalid_archive_ignore")

	var out bytes.Buffer
	r, err := render.New("json", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	mc := malcontent.Config{
		Concurrency:    runtime.NumCPU(),
		ExitExtraction: false,
		IgnoreSelf:     false,
		MinFileRisk:    0,
		MinRisk:        0,
		Renderer:       r,
		Rules:          yrs,
		ScanPaths: []string{
			"testdata/17419.zip",
			"testdata/joblib_0.9.4.dev0_compressed_cache_size_pickle_py35_np19.gz",
		},
	}
	res, err := Scan(ctx, mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Full(ctx, nil, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	got := out.String()
	want := "{}\n"
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch: (-want +got):\n%s", diff)
	}
}

func TestScanConflictingArchiveFiles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clog.FromContext(ctx).With("test", "scan_conflicting_archive_files")

	var out bytes.Buffer
	r, err := render.New("json", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	mc := malcontent.Config{
		Concurrency:    runtime.NumCPU(),
		ExitExtraction: false,
		IgnoreSelf:     false,
		MinFileRisk:    0,
		MinRisk:        0,
		Renderer:       r,
		Rules:          yrs,
		ScanPaths: []string{
			"testdata/conflict.zip",
		},
	}
	res, err := Scan(ctx, mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Full(ctx, nil, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	got := out.String()
	td, err := os.ReadFile("testdata/scan_conflict")
	if err != nil {
		t.Fatalf("testdata read failed: %v", err)
	}
	want := string(td)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch: (-want +got):\n%s", diff)
	}
}

func TestGetExt(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{
			path: "testdata/file.apk",
			want: ".apk",
		}, {
			path: "testdata/file.jar",
			want: ".jar",
		}, {
			path: "testdata/file.tar",
			want: ".tar",
		}, {
			path: "testdata/file.tgz",
			want: ".tgz",
		}, {
			path: "testdata/file.tar.gz",
			want: ".tar.gz",
		}, {
			path: "testdata/file.tar.xz",
			want: ".tar.xz",
		}, {
			path: "testdata/file.zip",
			want: ".zip",
		}, {
			path: "testdata/file_1.0.0",
			want: "",
		}, {
			path: "testdata/file_1.0.0.apk",
			want: ".apk",
		}, {
			path: "testdata/file_1.0.0.jar",
			want: ".jar",
		}, {
			path: "testdata/file_1.0.0.tar",
			want: ".tar",
		}, {
			path: "testdata/file_1.0.0.tgz",
			want: ".tgz",
		}, {
			path: "testdata/file_1.0.0.tar.gz",
			want: ".tar.gz",
		}, {
			path: "testdata/file_1.0.0.tar.xz",
			want: ".tar.xz",
		}, {
			path: "testdata/file_1.0.0.zip",
			want: ".zip",
		}, {
			path: "testdata/file.a.b.c.tar.gz",
			want: ".tar.gz",
		}, {
			path: "testdata/file_a.b.c.tar.xz",
			want: ".tar.xz",
		}, {
			path: "testdata/file_a.b.0.tar",
			want: ".tar",
		}, {
			path: "testdata/file_no_ext",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			if got := programkind.GetExt(tt.path); got != tt.want {
				t.Errorf("Ext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidPath(t *testing.T) {
	tmpRoot, err := os.MkdirTemp("", "isValidPath-*")
	if err != nil {
		t.Fatalf("Failed to create temp base directory: %v", err)
	}
	defer os.RemoveAll(tmpRoot)

	tempSubDir, err := os.MkdirTemp(tmpRoot, "isValidPathSub-*")
	if err != nil {
		t.Fatalf("Failed to create temp sub directory: %v", err)
	}

	tests := []struct {
		name     string
		target   string
		baseDir  string
		expected bool
	}{
		{
			name:     "Valid direct child path",
			target:   filepath.Join(tmpRoot, "file.txt"),
			baseDir:  tmpRoot,
			expected: true,
		},
		{
			name:     "Valid nested path",
			target:   filepath.Join(tempSubDir, "file.txt"),
			baseDir:  tmpRoot,
			expected: true,
		},
		{
			name:     "Invalid parent directory traversal",
			target:   filepath.Join(tmpRoot, "../file.txt"),
			baseDir:  tmpRoot,
			expected: false,
		},
		{
			name:     "Invalid absolute path outside base",
			target:   "/etc/passwd",
			baseDir:  tmpRoot,
			expected: false,
		},
		{
			name:     "Invalid relative path outside base",
			target:   "../../etc/passwd",
			baseDir:  tmpRoot,
			expected: false,
		},
		{
			name:     "Empty target path",
			target:   "",
			baseDir:  tmpRoot,
			expected: false,
		},
		{
			name:     "Empty base directory",
			target:   filepath.Join(tmpRoot, "file.txt"),
			baseDir:  "",
			expected: false,
		},
		{
			name:     "Path with irregular separators",
			target:   strings.ReplaceAll(filepath.Join(tmpRoot, "file.txt"), "/", "//"),
			baseDir:  tmpRoot,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := archive.IsValidPath(tt.target, tt.baseDir)
			if result != tt.expected {
				t.Errorf("isValidPath(%q, %q) = %v, want %v", tt.target, tt.baseDir, result, tt.expected)
			}
		})
	}
}
