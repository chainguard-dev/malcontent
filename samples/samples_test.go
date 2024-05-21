// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package samples

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/chainguard-dev/bincapz/pkg/action"
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
	ctx := slogtest.TestContextWithLogger(t)
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
			bc := action.Config{
				IgnoreSelf:     false,
				Renderer:       render,
				Rules:          yrs,
				MinResultScore: 1,
				ScanPaths:      []string{binPath},
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
	ctx := slogtest.TestContextWithLogger(t)
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

			bc := action.Config{
				IgnoreSelf: false,
				IgnoreTags: []string{"harmless"},
				Renderer:   simple,
				Rules:      yrs,
				ScanPaths:  []string{binPath},
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
	ctx := slogtest.TestContextWithLogger(t)
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
		{diff: "macOS/clean/ls.mdiff", format: "markdown", src: "Linux/clean/ls.x86_64", dest: "macOS/clean/ls"},
		{diff: "macOS/2023.3CX/libffmpeg.dirty.mdiff", format: "markdown", src: "macOS/2023.3CX/libffmpeg.dylib", dest: "macOS/2023.3CX/libffmpeg.dirty.dylib"},
		{diff: "Linux/2023.FreeDownloadManager/freedownloadmanager.sdiff", format: "simple", src: "Linux/2023.FreeDownloadManager/freedownloadmanager_clear_postinst", dest: "Linux/2023.FreeDownloadManager/freedownloadmanager_infected_postinst", minResultScore: 1, minFileScore: 0},
		{diff: "macOS/clean/ls.sdiff.level_2", format: "simple", src: "Linux/clean/ls.x86_64", dest: "macOS/clean/ls", minResultScore: 2, minFileScore: 2},
		{diff: "macOS/clean/ls.sdiff.trigger_2", format: "simple", src: "Linux/clean/ls.x86_64", dest: "macOS/clean/ls", minResultScore: 1, minFileScore: 2},
		// Important: minFileScore should apply to source or destination
		{diff: "macOS/clean/ls.sdiff.trigger_3", format: "simple", src: "Linux/clean/ls.x86_64", dest: "macOS/clean/ls", minResultScore: 1, minFileScore: 3},
		{diff: "Linux/2024.sbcl.market/sbcl.sdiff", format: "simple", src: "Linux/2024.sbcl.market/sbcl.clean", dest: "Linux/2024.sbcl.market/sbcl.dirty"},
	}

	for _, tc := range tests {
		t.Run(tc.diff, func(t *testing.T) {
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

			bc := action.Config{
				IgnoreSelf:     false,
				IgnoreTags:     []string{"harmless"},
				MinFileScore:   tc.minFileScore,
				MinResultScore: tc.minResultScore,
				Renderer:       simple,
				Rules:          yrs,
				ScanPaths:      []string{tc.src, tc.dest},
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
	ctx := slogtest.TestContextWithLogger(t)
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
		if !strings.HasSuffix(path, ".md") {
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

			bc := action.Config{
				IgnoreSelf: false,
				IgnoreTags: []string{"harmless"},
				Renderer:   simple,
				Rules:      yrs,
				ScanPaths:  []string{binPath},
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
