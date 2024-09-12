// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package samples

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/chainguard-dev/bincapz/pkg/action"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/compile"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/rules"
	thirdparty "github.com/chainguard-dev/bincapz/third_party"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
)

var testDataRoot = "."

func TestJSON(t *testing.T) {
	t.Parallel()
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "TestJSON")

	yrs, err := compile.Recursive(ctx, []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	fileSystem := os.DirFS(testDataRoot)

	fs.WalkDir(fileSystem, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		name := strings.ReplaceAll(path, ".json", "")
		jsonPath := path
		binPath := filepath.Join(testDataRoot, name)

		// must be a non-test JSON
		if _, err := os.Stat(binPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}

		t.Run(name, func(t *testing.T) {
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
			bc := bincapz.Config{
				Concurrency: runtime.NumCPU(),
				IgnoreSelf:  false,
				MinRisk:     1,
				Renderer:    render,
				Rules:       yrs,
				ScanPaths:   []string{binPath},
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)
			res, err := action.Scan(ctx, bc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if err := render.Full(ctx, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("json output mismatch: (-want +got):\n%s", diff)
			}
		})
		return nil
	})
}

func TestSimple(t *testing.T) {
	t.Parallel()
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "simple")

	yrs, err := compile.Recursive(ctx, []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	fileSystem := os.DirFS(testDataRoot)

	fs.WalkDir(fileSystem, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(path, ".simple") {
			return nil
		}

		name := strings.ReplaceAll(path, ".simple", "")
		testPath := path
		binPath := filepath.Join(testDataRoot, name)

		t.Run(name, func(t *testing.T) {
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

			bc := bincapz.Config{
				Concurrency: runtime.NumCPU(),
				IgnoreSelf:  false,
				IgnoreTags:  []string{"harmless"},
				Renderer:    simple,
				Rules:       yrs,
				ScanPaths:   []string{binPath},
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)
			res, err := action.Scan(ctx, bc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if err := simple.Full(ctx, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Simple output mismatch: (-want +got):\n%s", diff)
			}
		})
		return nil
	})
}

func TestDiff(t *testing.T) {
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "diff")

	yrs, err := compile.Recursive(ctx, []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	fileSystem := os.DirFS(testDataRoot)

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

			bc := bincapz.Config{
				Concurrency: runtime.NumCPU(),
				IgnoreSelf:  false,
				IgnoreTags:  []string{"harmless"},
				MinFileRisk: tc.minFileScore,
				MinRisk:     tc.minResultScore,
				Renderer:    simple,
				Rules:       yrs,
				ScanPaths:   []string{strings.TrimPrefix(tc.src, "../out/samples/"), strings.TrimPrefix(tc.dest, "../out/samples/")},
			}

			logger := clog.New(slog.Default().Handler()).With("src", tc.src)
			ctx := clog.WithLogger(context.Background(), logger)
			res, err := action.Diff(ctx, bc)
			if err != nil {
				t.Fatalf("diff failed: %v", err)
			}

			if err := simple.Full(ctx, res); err != nil {
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

func TestMarkdown(t *testing.T) {
	t.Parallel()
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "TestMarkDown")

	yrs, err := compile.Recursive(ctx, []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	fileSystem := os.DirFS(testDataRoot)

	fs.WalkDir(fileSystem, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(path, ".md") || strings.Contains(path, "README") {
			return nil
		}

		name := strings.ReplaceAll(path, ".md", "")
		testPath := path
		binPath := filepath.Join(testDataRoot, name)

		t.Run(name, func(t *testing.T) {
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

			bc := bincapz.Config{
				Concurrency:           runtime.NumCPU(),
				IgnoreSelf:            false,
				IgnoreTags:            []string{"harmless"},
				QuantityIncreasesRisk: true,
				Renderer:              simple,
				Rules:                 yrs,
				ScanPaths:             []string{binPath},
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)

			res, err := action.Scan(ctx, bc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if err := simple.Full(ctx, res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := reduceMarkdown(out.String())
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("markdown output mismatch: (-want +got):\n%s", diff)
			}
		})
		return nil
	})
}

func TestBincapzIgnored(t *testing.T) {
	t.Parallel()
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "scan_bincapz")

	yrs, err := compile.Recursive(ctx, []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	var out bytes.Buffer
	simple, err := render.New("simple", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	bc := bincapz.Config{
		IgnoreSelf:  true,
		IgnoreTags:  []string{"harmless"},
		Renderer:    simple,
		Rules:       yrs,
		ScanPaths:   []string{"macOS/clean/bincapz"},
		Concurrency: runtime.NumCPU(),
	}
	res, err := action.Scan(ctx, bc)
	if err != nil {
		t.Fatal(err)
	}
	if err := simple.Full(ctx, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	outBytes := out.Bytes()
	got := string(outBytes)

	want := ""
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("json output mismatch: (-want +got):\n%s", diff)
	}
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
		"does-nothing",
		"javascript",
		"linux",
		"macOS",
		"npm",
		"php",
		"python",
		"typescript",
		"windows",
	}
	if p != "" {
		paths = strings.Split(p, ",")
	}
	for i := 0; i < b.N; i++ {
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

		yrs, err := compile.Recursive(ctx, []fs.FS{rules.FS, thirdparty.FS})
		if err != nil {
			b.Fatalf("compile: %v", err)
		}

		var out bytes.Buffer
		simple, err := render.New("simple", &out)
		if err != nil {
			b.Fatalf("render: %v", err)
		}
		bc := bincapz.Config{
			Concurrency: runtime.NumCPU(),
			IgnoreSelf:  true,
			IgnoreTags:  []string{"harmless"},
			Renderer:    simple,
			Rules:       yrs,
			ScanPaths:   paths,
		}
		res, err := action.Scan(ctx, bc)
		if err != nil {
			b.Fatal(err)
		}
		if err := simple.Full(ctx, res); err != nil {
			b.Fatalf("full: %v", err)
		}
	}
	return bench
}
