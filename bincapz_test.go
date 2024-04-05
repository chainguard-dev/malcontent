// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/bincapz/pkg/action"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/pkg/rules"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
)

var testDataRoot = "testdata"

func TestJSON(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)
	clog.FromContext(ctx).With("test", "TestJSON")

	yrs, err := rules.Compile(ctx, ruleFs, false)
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

			var want bincapz.Report
			if err := json.Unmarshal(td, &want); err != nil {
				t.Fatalf("testdata unmarshal: %v", err)
			}

			var out bytes.Buffer
			render, err := render.New("json", &out)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			bc := action.Config{
				ScanPaths:  []string{binPath},
				IgnoreTags: []string{"harmless"},
				Renderer:   render,
				Rules:      yrs,
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)
			got, err := action.Scan(ctx, bc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if diff := cmp.Diff(*got, want); diff != "" {
				t.Errorf("unexpected diff: %s", diff)
			}
		})
		return nil
	})
}

func TestSimple(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)
	clog.FromContext(ctx).With("test", "simple")

	yrs, err := rules.Compile(ctx, ruleFs, false)
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
				ScanPaths:  []string{binPath},
				IgnoreTags: []string{"harmless"},
				Renderer:   simple,
				Rules:      yrs,
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)
			res, err := action.Scan(ctx, bc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if err := simple.Full(ctx, *res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(got, want); diff != "" {
				t.Errorf("unexpected diff: %s\ngot: %s", diff, got)
			}
		})
		return nil
	})
}

func TestDiff(t *testing.T) {
	yrs, err := rules.Compile(context.TODO(), ruleFs, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	fileSystem := os.DirFS(testDataRoot)

	tests := []struct {
		diff   string
		format string
		src    string
		dest   string
	}{
		{"Linux/freedownloadmanager.sdiff", "simple", "testdata/Linux/freedownloadmanager_clear_postinst", "testdata/Linux/freedownloadmanager_infected_postinst"},
		{"macOS/libffmpeg.dirty.mdiff", "markdown", "testdata/macOS/libffmpeg.dylib", "testdata/macOS/libffmpeg.dirty.dylib"},
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
				ScanPaths:  []string{tc.src, tc.dest},
				IgnoreTags: []string{"harmless"},
				Renderer:   simple,
				Rules:      yrs,
			}

			logger := clog.New(slog.Default().Handler()).With("src", tc.src)
			ctx := clog.WithLogger(context.Background(), logger)
			res, err := action.Diff(ctx, bc)

			if err != nil {
				t.Fatalf("diff failed: %v", err)
			}

			if err := simple.Full(ctx, *res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(got, want); diff != "" {
				t.Errorf("unexpected diff: %s", diff)
			}
		})
	}
}

func TestMarkdown(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)
	clog.FromContext(ctx).With("test", "TestMarkDown")
	yrs, err := rules.Compile(ctx, ruleFs, false)
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

			want := string(td)
			var out bytes.Buffer
			simple, err := render.New("markdown", &out)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			bc := action.Config{
				ScanPaths:  []string{binPath},
				IgnoreTags: []string{"harmless"},
				Renderer:   simple,
				Rules:      yrs,
			}

			tcLogger := clog.FromContext(ctx).With("test", name)
			ctx := clog.WithLogger(ctx, tcLogger)

			res, err := action.Scan(ctx, bc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if err := simple.Full(ctx, *res); err != nil {
				t.Fatalf("full: %v", err)
			}

			got := out.String()
			if diff := cmp.Diff(got, want); diff != "" {
				t.Errorf("unexpected diff: %s\ngot: %s", diff, got)
			}
		})
		return nil
	})
}
