// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"github.com/google/go-cmp/cmp"
)

// readTestFile reads a file using file.GetContents for consistency with production code.
func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open test file %s: %v", path, err)
	}
	defer f.Close()
	buf := make([]byte, file.ExtractBuffer)
	data, err := file.GetContents(f, buf)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", path, err)
	}
	return data
}

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
			defer os.RemoveAll(dir)
			dirFiles, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(dirFiles) != len(tt.want) {
				t.Fatalf("unexpected number of files in dir: %d", len(dirFiles))
			}
			got := make([]string, 0, len(dirFiles))
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
	defer os.RemoveAll(dir)
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
	defer os.RemoveAll(dir)
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
	defer os.RemoveAll(dir)
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
	defer os.RemoveAll(dir)
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

	td := readTestFile(t, "testdata/scan_archive")
	want := string(td)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch: (-want +got):\n%s", diff)
	}
}

func TestScanDeb(t *testing.T) {
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
		ScanPaths:   []string{"testdata/yara.deb"},
	}
	res, err := Scan(ctx, mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Full(ctx, nil, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	got := out.String()

	td := readTestFile(t, "testdata/scan_deb")
	want := string(td)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch: (-want +got):\n%s", diff)
	}
}

func TestScanRPM(t *testing.T) {
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
		ScanPaths:   []string{"testdata/yara.rpm"},
	}
	res, err := Scan(ctx, mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Full(ctx, nil, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	got := out.String()

	td := readTestFile(t, "testdata/scan_rpm")
	want := string(td)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch: (-want +got):\n%s", diff)
	}
}

func TestScanZlib(t *testing.T) {
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
		ScanPaths:   []string{"testdata/yara.tar.zlib"},
	}
	res, err := Scan(ctx, mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Full(ctx, nil, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	got := out.String()

	td := readTestFile(t, "testdata/scan_zlib")
	want := string(td)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch: (-want +got):\n%s", diff)
	}
}

func TestScanZstd(t *testing.T) {
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
		ScanPaths:   []string{"testdata/yara.tar.zst"},
	}
	res, err := Scan(ctx, mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Full(ctx, nil, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	got := out.String()

	td := readTestFile(t, "testdata/scan_zstd")
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
	td := readTestFile(t, "testdata/scan_conflict")
	want := string(td)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch: (-want +got):\n%s", diff)
	}
}

// createBrokenNestedArchive creates a tar.gz file containing a nested
// file with an archive extension whose content is valid gzip but invalid tar.
func createBrokenNestedArchive(t *testing.T, dir string) string {
	t.Helper()

	outPath := filepath.Join(dir, "outer.tar.gz")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("failed to create outer archive: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	var innerBuf bytes.Buffer
	innerGw := gzip.NewWriter(&innerBuf)
	if _, err := innerGw.Write(bytes.Repeat([]byte("A"), 1024)); err != nil {
		t.Fatalf("failed to write inner gzip data: %v", err)
	}
	if err := innerGw.Close(); err != nil {
		t.Fatalf("failed to close inner gzip writer: %v", err)
	}

	innerData := innerBuf.Bytes()
	if err := tw.WriteHeader(&tar.Header{
		Name: "bad_nested.tar.gz",
		Mode: 0o600,
		Size: int64(len(innerData)),
	}); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}
	if _, err := tw.Write(innerData); err != nil {
		t.Fatalf("failed to write tar data: %v", err)
	}

	return outPath
}

// TestNestedFailureRetention verifies that when a nested archive
// extraction fails with ExitExtraction=false (default), the original nested archive
// file is retained in the extraction directory for scanning rather than being deleted.
func TestNestedFailureRetention(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("", "nested-fail-retain-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	outerArchive := createBrokenNestedArchive(t, tmpDir)

	ctx := context.Background()
	cfg := malcontent.Config{ExitExtraction: false}

	extractDir, err := archive.ExtractArchiveToTempDir(ctx, cfg, outerArchive)
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir should not fail with ExitExtraction=false, got: %v", err)
	}
	defer os.RemoveAll(extractDir)

	// The nested archive file must still exist so it can be scanned as a regular file
	found := false
	err = filepath.WalkDir(extractDir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == "bad_nested.tar.gz" {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk extraction directory: %v", err)
	}
	if !found {
		t.Fatal("nested archive file was deleted after extraction failure but should be retained for scanning")
	}
}

// TestNestedFailureRetentionError verifies that when ExitExtraction=true,
// a nested archive extraction failure propagates as an error.
func TestNestedFailureRetentionError(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("", "nested-fail-exit-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	outerArchive := createBrokenNestedArchive(t, tmpDir)

	ctx := context.Background()
	cfg := malcontent.Config{ExitExtraction: true}

	extractDir, err := archive.ExtractArchiveToTempDir(ctx, cfg, outerArchive)
	if extractDir != "" {
		defer os.RemoveAll(extractDir)
	}
	if err == nil {
		t.Fatal("ExtractArchiveToTempDir should return error with ExitExtraction=true for nested archives which cannot be extracted")
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
