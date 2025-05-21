// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package samples

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/chainguard-dev/malcontent/pkg/action"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"github.com/google/go-cmp/cmp"

	yarax "github.com/VirusTotal/yara-x/go"
)

var (
	err         error
	rfs         = []fs.FS{rules.FS, thirdparty.FS}
	sampleDir   = ""
	testDataDir = ""
	yrs         *yarax.Rules
)

func init() {
	flag.StringVar(&sampleDir, "sample_dir",
		"../out/chainguard-dev/malcontent-samples",
		"root directory of sample data, typically checked out from https://github.com/chainguard-dev/malcontent-samples via 'make integration'")

	_, me, _, _ := runtime.Caller(0) //nolint:dogsled // don't need the rest
	testDataDir = filepath.Dir(me)
	fmt.Printf(">>> test data dir: %s\n", testDataDir)
	fmt.Printf(">>> sample data dir: %s\n", sampleDir)

	if _, err := os.Stat(sampleDir); err != nil {
		fmt.Printf("samples directory %q does not exist - please use 'make integration' or git clone https://github.com/chainguard-dev/malcontent-samples appropriately. This path may be overridden by --sample_dir", sampleDir)
		os.Exit(1)
	}

	ctx := context.Background()
	yrs, err = action.CachedRules(ctx, rfs)
	if err != nil {
		fmt.Printf("failed to compile rules")
	}
}

func TestJSON(t *testing.T) {
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "TestJSON")

	fileSystem := os.DirFS(testDataDir)
	os.Chdir(sampleDir)

	fs.WalkDir(fileSystem, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		name := strings.ReplaceAll(path, ".json", "")
		jsonPath := path
		binPath := name

		// must be a non-test JSON
		if _, err := os.Stat(binPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			td, err := fs.ReadFile(fileSystem, jsonPath)
			if err != nil {
				t.Fatalf("testdata read failed: %v", err)
			}
			want := string(td)

			var out bytes.Buffer
			render, err := render.New("json", &out)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			mc := malcontent.Config{
				Concurrency:           runtime.NumCPU(),
				IgnoreSelf:            false,
				MinFileRisk:           1,
				MinRisk:               1,
				QuantityIncreasesRisk: true,
				Renderer:              render,
				Rules:                 yrs,
				ScanPaths:             []string{binPath},
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)
			res, err := action.Scan(ctx, mc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if err := render.Full(ctx, nil, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("json output mismatch: (-want +got):\n%s", diff)
			}

			res.Files.Range(func(_, value any) bool {
				if r, ok := value.(*malcontent.FileReport); ok {
					if strings.Contains(binPath, "/clean/") && r.RiskScore > 2 {
						t.Errorf("%s score too high for a 'clean' sample: %s [%d]:\n%s", binPath, r.RiskLevel, r.RiskScore, got)
					}
				}
				return true
			})
		})
		return nil
	})
}

func TestJSONStats(t *testing.T) {
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "TestJSON")

	fileSystem := os.DirFS(testDataDir)
	os.Chdir(sampleDir)

	fs.WalkDir(fileSystem, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(path, ".stats.json") {
			return nil
		}

		name := strings.ReplaceAll(path, ".stats.json", "")
		jsonPath := path
		binPath := name

		// must be a non-test JSON
		if _, err := os.Stat(binPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			td, err := fs.ReadFile(fileSystem, jsonPath)
			if err != nil {
				t.Fatalf("testdata read failed: %v", err)
			}
			want := string(td)

			var out bytes.Buffer
			render, err := render.New("json", &out)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			mc := malcontent.Config{
				Concurrency: runtime.NumCPU(),
				IgnoreSelf:  false,
				MinFileRisk: 1,
				MinRisk:     1,
				Renderer:    render,
				Rules:       yrs,
				ScanPaths:   []string{binPath},
				Stats:       true,
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)
			res, err := action.Scan(ctx, mc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if err := render.Full(ctx, &mc, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("json output mismatch: (-want +got):\n%s", diff)
			}

			res.Files.Range(func(_, value any) bool {
				if r, ok := value.(*malcontent.FileReport); ok {
					if strings.Contains(binPath, "/clean/") && r.RiskScore > 2 {
						t.Errorf("%s score too high for a 'clean' sample: %s [%d]:\n%s", binPath, r.RiskLevel, r.RiskScore, got)
					}
				}
				return true
			})
		})
		return nil
	})
}

func TestSimple(t *testing.T) {
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "simple")

	fileSystem := os.DirFS(testDataDir)
	os.Chdir(sampleDir)

	fs.WalkDir(fileSystem, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(path, ".simple") {
			return nil
		}

		name := strings.ReplaceAll(path, ".simple", "")
		testPath := path

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			binPath := name
			binDir := filepath.Dir(binPath)
			if _, err := os.Stat(binPath); err != nil {
				t.Fatalf("test program missing: %s\ncontents of %s: %v", binPath, binDir, testInputs(binDir))
			}

			td, err := fs.ReadFile(fileSystem, testPath)
			if err != nil {
				t.Fatalf("testdata read failed: %v", err)
			}

			want := string(td)
			var out bytes.Buffer
			simple, err := render.New("simple", &out)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			mc := malcontent.Config{
				Concurrency:           runtime.NumCPU(),
				IgnoreSelf:            false,
				IgnoreTags:            []string{"harmless"},
				MinFileRisk:           1,
				MinRisk:               1,
				QuantityIncreasesRisk: true,
				Renderer:              simple,
				Rules:                 yrs,
				ScanPaths:             []string{binPath},
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)
			res, err := action.Scan(ctx, mc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if err := simple.Full(ctx, nil, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Simple output mismatch: (-want +got):\n%s", diff)
			}

			// Eeek. We shouldn't be returning such an awkward object in a public interface
			res.Files.Range(func(_, value any) bool {
				if r, ok := value.(*malcontent.FileReport); ok {
					if strings.Contains(binPath, "/clean/") && r.RiskScore > 2 {
						t.Errorf("%s score too high for a 'clean' sample: %s [%d]:\n%s", binPath, r.RiskLevel, r.RiskScore, got)
					}
				}
				return true
			})
		})
		return nil
	})
}

func TestDiff(t *testing.T) {
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "diff")

	fileSystem := os.DirFS(testDataDir)
	os.Chdir(sampleDir)

	tests := []struct {
		diff           string
		format         string
		src            string
		dest           string
		minResultScore int
		minFileScore   int
	}{
		{diff: "macOS/clean/ls.mdiff", format: "markdown", src: "linux/clean/ls.x86_64", dest: "macOS/clean/ls"},
		{diff: "macOS/2023.3CX/libffmpeg.dirty.mdiff", format: "markdown", src: "macOS/2023.3CX/libffmpeg.dylib", dest: "macOS/2023.3CX/libffmpeg.dirty.dylib"},
		{diff: "linux/2023.FreeDownloadManager/freedownloadmanager.sdiff", format: "simple", src: "linux/2023.FreeDownloadManager/freedownloadmanager_clear_postinst", dest: "linux/2023.FreeDownloadManager/freedownloadmanager_infected_postinst", minResultScore: 1, minFileScore: 0},
		{diff: "macOS/clean/ls.sdiff.level_2", format: "simple", src: "linux/clean/ls.x86_64", dest: "macOS/clean/ls", minResultScore: 2, minFileScore: 2},
		{diff: "macOS/clean/ls.sdiff.trigger_2", format: "simple", src: "linux/clean/ls.x86_64", dest: "macOS/clean/ls", minResultScore: 1, minFileScore: 2},
		// Important: minFileScore should apply to source or destination
		{diff: "macOS/clean/ls.sdiff.trigger_3", format: "simple", src: "linux/clean/ls.x86_64", dest: "macOS/clean/ls", minResultScore: 1, minFileScore: 3},
		{diff: "linux/2024.sbcl.market/sbcl.sdiff", format: "simple", src: "linux/2024.sbcl.market/sbcl.clean", dest: "linux/2024.sbcl.market/sbcl.dirty"},
		{diff: "linux/clean/aws-c-io/aws-c-io.sdiff", format: "simple", src: "linux/clean/aws-c-io/aws-c-io-0.14.10-r0.spdx.json", dest: "linux/clean/aws-c-io/aws-c-io-0.14.11-r0.spdx.json"},
	}

	for _, tc := range tests {
		t.Run(tc.diff, func(t *testing.T) {
			t.Parallel()
			td, err := fs.ReadFile(fileSystem, tc.diff)
			if err != nil {
				t.Fatalf("testdata read failed: %v", err)
			}

			want := string(td)
			var out bytes.Buffer
			simple, err := render.New(tc.format, &out)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			mc := malcontent.Config{
				Concurrency: runtime.NumCPU(),
				IgnoreSelf:  false,
				IgnoreTags:  []string{"harmless"},
				MinFileRisk: tc.minFileScore,
				MinRisk:     tc.minResultScore,
				Renderer:    simple,
				Rules:       yrs,
				ScanPaths:   []string{tc.src, tc.dest},
			}

			logger := clog.New(slog.Default().Handler()).With("src", tc.src)
			ctx := clog.WithLogger(context.Background(), logger)
			res, err := action.Diff(ctx, mc, logger)
			if err != nil {
				t.Fatalf("diff failed: %v", err)
			}

			if err := simple.Full(ctx, nil, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("simple diff output mismatch: (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDiffFileChange(t *testing.T) {
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "diff")

	fileSystem := os.DirFS(testDataDir)
	os.Chdir(sampleDir)

	tests := []struct {
		diff           string
		format         string
		src            string
		dest           string
		minResultScore int
		minFileScore   int
	}{
		{diff: "macOS/2023.3CX/libffmpeg.change_increase.mdiff", format: "markdown", src: "macOS/2023.3CX/libffmpeg.dylib", dest: "macOS/2023.3CX/libffmpeg.dirty.dylib"},
		{diff: "macOS/2023.3CX/libffmpeg.change_decrease.mdiff", format: "markdown", src: "macOS/2023.3CX/libffmpeg.dirty.dylib", dest: "macOS/2023.3CX/libffmpeg.dylib"},
		{diff: "macOS/2023.3CX/libffmpeg.change_no_change.mdiff", format: "markdown", src: "macOS/2023.3CX/libffmpeg.dylib", dest: "macOS/2023.3CX/libffmpeg.dylib"},
		{diff: "macOS/2023.3CX/libffmpeg.change_unrelated.mdiff", format: "markdown", src: "macOS/2023.3CX/libffmpeg.dylib", dest: "macOS/clean/ls"},
	}

	for _, tc := range tests {
		t.Run(tc.diff, func(t *testing.T) {
			t.Parallel()
			td, err := fs.ReadFile(fileSystem, tc.diff)
			if err != nil {
				t.Fatalf("testdata read failed: %v", err)
			}

			want := string(td)
			var out bytes.Buffer
			simple, err := render.New(tc.format, &out)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			mc := malcontent.Config{
				Concurrency:    runtime.NumCPU(),
				FileRiskChange: true,
				IgnoreSelf:     false,
				IgnoreTags:     []string{"harmless"},
				MinFileRisk:    tc.minFileScore,
				MinRisk:        tc.minResultScore,
				Renderer:       simple,
				Rules:          yrs,
				ScanPaths:      []string{strings.TrimPrefix(tc.src, "../out/chainguard-dev/malcontent-samples/"), strings.TrimPrefix(tc.dest, "../out/chainguard-dev/malcontent-samples/")},
			}

			logger := clog.New(slog.Default().Handler()).With("src", tc.src)
			ctx := clog.WithLogger(context.Background(), logger)
			res, err := action.Diff(ctx, mc, logger)
			if err != nil {
				t.Fatalf("diff failed: %v", err)
			}

			if err := simple.Full(ctx, nil, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("simple diff output mismatch: (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDiffFileIncrease(t *testing.T) {
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "diff")

	fileSystem := os.DirFS(testDataDir)
	os.Chdir(sampleDir)

	tests := []struct {
		diff           string
		format         string
		src            string
		dest           string
		minResultScore int
		minFileScore   int
	}{
		{diff: "macOS/2023.3CX/libffmpeg.increase.mdiff", format: "markdown", src: "macOS/2023.3CX/libffmpeg.dylib", dest: "macOS/2023.3CX/libffmpeg.dirty.dylib"},
		{diff: "macOS/2023.3CX/libffmpeg.decrease.mdiff", format: "markdown", src: "macOS/2023.3CX/libffmpeg.dirty.dylib", dest: "macOS/2023.3CX/libffmpeg.dylib"},
		{diff: "macOS/2023.3CX/libffmpeg.no_change.mdiff", format: "markdown", src: "macOS/2023.3CX/libffmpeg.dylib", dest: "macOS/2023.3CX/libffmpeg.dylib"},
		{diff: "macOS/2023.3CX/libffmpeg.increase_unrelated.mdiff", format: "markdown", src: "macOS/clean/ls", dest: "macOS/2023.3CX/libffmpeg.dylib"},
	}

	for _, tc := range tests {
		t.Run(tc.diff, func(t *testing.T) {
			t.Parallel()
			td, err := fs.ReadFile(fileSystem, tc.diff)
			if err != nil {
				t.Fatalf("testdata read failed: %v", err)
			}

			want := string(td)
			var out bytes.Buffer
			simple, err := render.New(tc.format, &out)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			mc := malcontent.Config{
				Concurrency:      runtime.NumCPU(),
				FileRiskIncrease: true,
				IgnoreSelf:       false,
				IgnoreTags:       []string{"harmless"},
				MinFileRisk:      tc.minFileScore,
				MinRisk:          tc.minResultScore,
				Renderer:         simple,
				Rules:            yrs,
				ScanPaths:        []string{strings.TrimPrefix(tc.src, "../out/chainguard-dev/malcontent-samples/"), strings.TrimPrefix(tc.dest, "../out/chainguard-dev/malcontent-samples/")},
			}

			logger := clog.New(slog.Default().Handler()).With("src", tc.src)
			ctx := clog.WithLogger(context.Background(), logger)
			res, err := action.Diff(ctx, mc, logger)
			if err != nil {
				t.Fatalf("diff failed: %v", err)
			}

			if err := simple.Full(ctx, nil, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("simple diff output mismatch: (-want +got):\n%s", diff)
			}
		})
	}
}

// reduceMarkdown reduces markdown output to simply diff output.
func reduceMarkdown(s string) string {
	spaceRe := regexp.MustCompile(` +`)
	dashRe := regexp.MustCompile(` -`)

	s = spaceRe.ReplaceAllString(s, " ")
	s = dashRe.ReplaceAllString(s, " ")
	return s
}

// test error helper to list files.
func testInputs(path string) string {
	fss, err := os.ReadDir(path)
	if err != nil {
		return err.Error()
	}
	names := []string{}

	for _, f := range fss {
		if strings.HasSuffix(f.Name(), ".simple") || strings.HasSuffix(f.Name(), ".md") {
			continue
		}
		if f.IsDir() {
			names = append(names, f.Name()+"/")
			continue
		}
		names = append(names, f.Name())
	}
	return strings.Join(names, " ")
}

func TestMarkdown(t *testing.T) {
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "TestMarkDown")

	fileSystem := os.DirFS(testDataDir)
	os.Chdir(sampleDir)

	fs.WalkDir(fileSystem, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(path, ".md") || strings.Contains(path, "README") {
			return nil
		}

		name := strings.ReplaceAll(path, ".md", "")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			binPath := name
			binDir := filepath.Dir(binPath)
			if _, err := os.Stat(binPath); err != nil {
				t.Fatalf("test program missing: %s\ncontents of %s: %v", binPath, binDir, testInputs(binDir))
			}

			testPath := path
			td, err := fs.ReadFile(fileSystem, testPath)
			if err != nil {
				t.Fatalf("testdata read failed: %v", err)
			}

			want := reduceMarkdown(string(td))
			var out bytes.Buffer
			simple, err := render.New("markdown", &out)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			mc := malcontent.Config{
				Concurrency:           runtime.NumCPU(),
				IgnoreSelf:            false,
				IgnoreTags:            []string{"harmless"},
				MinFileRisk:           1,
				MinRisk:               1,
				QuantityIncreasesRisk: true,
				Renderer:              simple,
				Rules:                 yrs,
				ScanPaths:             []string{binPath},
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)

			res, err := action.Scan(ctx, mc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if err := simple.Full(ctx, nil, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := reduceMarkdown(out.String())
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("markdown output mismatch: (-want +got):\n%s", diff)
			}

			res.Files.Range(func(_, value any) bool {
				if r, ok := value.(*malcontent.FileReport); ok {
					if strings.Contains(binPath, "/clean/") && r.RiskScore > 2 {
						t.Errorf("%s score too high for a 'clean' sample: %s [%d]:\n%s", binPath, r.RiskLevel, r.RiskScore, got)
					}
				}
				return true
			})
		})
		return nil
	})
}

// Allow for programmatic overrides of paths for benchmarks (defaults to all paths).
var overridePath string

func init() {
	flag.StringVar(&overridePath, "path", "", "override path for benchmarks")
}

// BenchmarkRun is the entrypoint for each benchmark run.
func BenchmarkRun(b *testing.B) {
	Benchmarks(b, overridePath)
}

// Benchmarks runs the appropriate benchmarks given the value of p (overridePath).
func Benchmarks(b *testing.B, p string) {
	// Default to all paths ("")
	paths := []string{
		sampleDir + "does-nothing",
		sampleDir + "javascript",
		sampleDir + "linux",
		sampleDir + "macOS",
		sampleDir + "npm",
		sampleDir + "php",
		sampleDir + "python",
		sampleDir + "typescript",
		sampleDir + "windows",
	}
	if p != "" {
		paths = strings.Split(p, ",")
	}
	for b.Loop() {
		bench := Template(b, paths)
		bench()
	}
}

// Template returns a benchmark function for use in Benchmarks.
//
//nolint:thelper // ignore template function for benchmarks
func Template(b *testing.B, paths []string) func() {
	bench := func() {
		ctx := context.TODO()
		clog.FromContext(ctx).With("benchmark", "samples")

		var out bytes.Buffer
		simple, err := render.New("simple", &out)
		if err != nil {
			b.Fatalf("render: %v", err)
		}
		mc := malcontent.Config{
			Concurrency: runtime.NumCPU(),
			IgnoreSelf:  true,
			IgnoreTags:  []string{"harmless"},
			Renderer:    simple,
			Rules:       yrs,
			ScanPaths:   paths,
		}
		res, err := action.Scan(ctx, mc)
		if err != nil {
			b.Fatal(err)
		}
		if err := simple.Full(ctx, nil, res); err != nil {
			b.Fatalf("full: %v", err)
		}
	}
	return bench
}
