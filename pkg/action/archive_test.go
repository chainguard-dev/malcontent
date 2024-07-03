package action

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/chainguard-dev/bincapz/pkg/compile"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/rules"
	thirdparty "github.com/chainguard-dev/bincapz/third_party"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
)

func TestExtractionMethod(t *testing.T) {
	tests := []struct {
		name string
		ext  string
		want func(context.Context, string, string) error
	}{
		{"apk", ".apk", extractTar},
		{"gem", ".gem", extractTar},
		{"gzip", ".gz", extractGzip},
		{"jar", ".jar", extractZip},
		{"tar.gz", ".tar.gz", extractTar},
		{"tar.xz", ".tar.xz", extractTar},
		{"tar", ".tar", extractTar},
		{"tgz", ".tgz", extractTar},
		{"unknown", ".unknown", nil},
		{"upx", ".upx", nil},
		{"zip", ".zip", extractZip},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := extractionMethod(tt.ext)
			if (got == nil) != (tt.want == nil) {
				t.Errorf("extractionMethod() for extension %v did not return expected result", tt.ext)
			}
		})
	}
}

func TestExtractionMultiple(t *testing.T) {
	t.Parallel()
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
		tt := tt
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			dir, err := extractArchiveToTempDir(ctx, tt.path)
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
	dir, err := extractArchiveToTempDir(ctx, filepath.Join("testdata", "apko.tar.gz"))
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
	var got []string
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
	dir, err := extractArchiveToTempDir(ctx, filepath.Join("testdata", "apko.gz"))
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
	var got []string
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
	dir, err := extractArchiveToTempDir(ctx, filepath.Join("testdata", "apko.zip"))
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
	var got []string
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
	dir, err := extractArchiveToTempDir(ctx, filepath.Join("testdata", "apko_nested.tar.gz"))
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
	var got []string
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
	ctx := slogtest.TestContextWithLogger(t)
	clog.FromContext(ctx).With("test", "scan_archive")

	yrs, err := compile.Recursive(ctx, []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	var out bytes.Buffer
	simple, err := render.New("simple", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	bc := Config{
		IgnoreSelf: false,
		IgnoreTags: []string{"harmless"},
		Renderer:   simple,
		Rules:      yrs,
		ScanPaths:  []string{"testdata/apko_nested.tar.gz"},
	}
	res, err := Scan(ctx, bc)
	if err != nil {
		t.Fatal(err)
	}
	if err := simple.Full(ctx, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	outBytes := out.Bytes()

	// Sort the output to ensure consistent ordering
	sorted := func(input []byte) []byte {
		lines := strings.Split(string(input), "\n")
		sort.Strings(lines)
		return []byte(strings.Join(lines, "\n"))
	}
	sortedBytes := sorted(outBytes)
	got := string(sortedBytes)

	td, err := os.ReadFile("testdata/scan_archive")
	if err != nil {
		t.Fatalf("testdata read failed: %v", err)
	}
	want := string(td)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("json output mismatch: (-want +got):\n%s", diff)
	}
}
