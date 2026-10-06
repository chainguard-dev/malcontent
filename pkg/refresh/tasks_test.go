// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package refresh

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/action"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/release"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// refreshTouch creates an empty file at path along with its parent directories.
func refreshTouch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

// refreshActionInputs creates empty stand-ins for every pkg/action input
// beneath root. actionRefresh only checks that its inputs exist.
func refreshActionInputs(t *testing.T, root string) {
	t.Helper()
	for _, td := range actionTestData {
		refreshTouch(t, filepath.Join(root, td.scanPath))
	}
}

// refreshDiffSamples returns a samples directory holding empty stand-ins for
// every diff source and destination. diffRefresh only checks that they exist.
func refreshDiffSamples(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, td := range diffTestData {
		refreshTouch(t, filepath.Join(root, td.srcPath))
		refreshTouch(t, filepath.Join(root, td.destPath))
	}
	return root
}

// refreshFakeUPX returns a regular, owner-only executable file that passes the
// MALCONTENT_UPX_PATH checks. Refresh validates the path but never runs it.
func refreshFakeUPX(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits required for the UPX path checks")
	}
	p := filepath.Join(t.TempDir(), "upx")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("WriteFile(%q): %v", p, err)
	}
	if err := os.Chmod(p, 0o700); err != nil {
		t.Fatalf("Chmod(%q): %v", p, err)
	}
	return p
}

// refreshByOutput indexes refresh tasks by their output path.
func refreshByOutput(tasks []TestData) map[string]TestData {
	m := make(map[string]TestData, len(tasks))
	for _, td := range tasks {
		m[td.OutputPath] = td
	}
	return m
}

func TestDiscoverTestDataSkipsDirectoriesAndActionTestdata(t *testing.T) {
	t.Parallel()
	samples := t.TempDir()
	goldens := t.TempDir()

	for _, rel := range []string{"linux/sample", "pkg/action/testdata/skipped", "bundle"} {
		refreshTouch(t, filepath.Join(samples, rel))
	}
	refreshTouch(t, filepath.Join(goldens, "linux/sample.simple"))
	refreshTouch(t, filepath.Join(goldens, "pkg/action/testdata/skipped.json"))
	// A directory whose name carries a golden extension is not a golden file.
	if err := os.MkdirAll(filepath.Join(goldens, "bundle.json"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	got, err := discoverTestData(Config{SamplesPath: samples, TestDataPath: goldens})
	if err != nil {
		t.Fatalf("discoverTestData() error: got = %v, want = nil", err)
	}
	want := map[string]string{
		filepath.Join(goldens, "linux/sample.simple"): filepath.Join(samples, "linux/sample"),
	}
	if !maps.Equal(got, want) {
		t.Errorf("discoverTestData(): got = %v, want = %v", got, want)
	}
}

func TestRefreshReportsConfigurationErrors(t *testing.T) {
	// Not parallel: subtests set MALCONTENT_UPX_PATH for the whole process,
	// and the working directory is moved to an empty directory so the
	// relative pkg/action inputs are never found.
	t.Chdir(t.TempDir())
	t.Cleanup(release.ResetRuleURLRef)
	upx := refreshFakeUPX(t)
	logger := clog.FromContext(t.Context())

	notDir := filepath.Join(t.TempDir(), "samples.txt")
	refreshTouch(t, notDir)

	tests := []struct {
		name    string
		upxPath string
		config  Config
		wantMsg string
		wantIs  error
	}{
		{
			name:    "invalid UPX path",
			upxPath: "bin/upx",
			config:  Config{SamplesPath: t.TempDir(), TestDataPath: t.TempDir(), Concurrency: 1},
			wantMsg: "required UPX installation not found",
			wantIs:  programkind.ErrUPXPathInvalid,
		},
		{
			name:    "missing samples path",
			upxPath: upx,
			config:  Config{TestDataPath: t.TempDir(), Concurrency: 1},
			wantMsg: "sample location is required",
		},
		{
			name:    "missing test data path",
			upxPath: upx,
			config:  Config{SamplesPath: t.TempDir(), Concurrency: 1},
			wantMsg: "test data location required",
		},
		{
			name:    "samples path that does not exist",
			upxPath: upx,
			config:  Config{SamplesPath: filepath.Join(t.TempDir(), "missing"), TestDataPath: t.TempDir(), Concurrency: 1},
			wantMsg: "sample directory not found",
			wantIs:  fs.ErrNotExist,
		},
		{
			name:    "samples path that is a file",
			upxPath: upx,
			config:  Config{SamplesPath: notDir, TestDataPath: t.TempDir(), Concurrency: 1},
			wantMsg: "sample path is not a directory",
		},
		{
			name:    "preparation failure",
			upxPath: upx,
			config:  Config{SamplesPath: t.TempDir(), TestDataPath: t.TempDir(), Concurrency: 1},
			wantMsg: "failed to prepare sample data refresh",
			wantIs:  fs.ErrNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MALCONTENT_UPX_PATH", tt.upxPath)
			err := Refresh(t.Context(), tt.config, logger)
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("Refresh() error: got = %v, want one containing %q", err, tt.wantMsg)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("Refresh() error: got = %v, want one matching %v", err, tt.wantIs)
			}
		})
	}
}

func TestActionRefreshBuildsScanTasks(t *testing.T) {
	// Not parallel: actionRefresh resolves its inputs against the working
	// directory.
	root := t.TempDir()
	refreshActionInputs(t, root)
	t.Chdir(root)

	tasks, err := actionRefresh(t.Context())
	t.Cleanup(func() { closeTestDataFiles(tasks) })
	if err != nil {
		t.Fatalf("actionRefresh() error: got = %v, want = nil", err)
	}
	if len(tasks) != len(actionTestData) {
		t.Fatalf("task count: got = %d, want = %d", len(tasks), len(actionTestData))
	}

	if got := tasks[0]; got.OutputPath != "pkg/action/testdata/scan_oci" ||
		!slices.Equal(got.Config.ScanPaths, []string{"pkg/action/testdata/static.tar.xz"}) {
		t.Errorf("first task: got output = %q, scan paths = %v, want output = %q, scan paths = [%s]",
			got.OutputPath, got.Config.ScanPaths, "pkg/action/testdata/scan_oci", "pkg/action/testdata/static.tar.xz")
	}

	for i, task := range tasks {
		want := actionTestData[i]
		if task.OutputPath != want.outputPath {
			t.Errorf("task %d output: got = %q, want = %q", i, task.OutputPath, want.outputPath)
		}
		if task.OutFile == nil {
			t.Errorf("task %d output file: got = nil, want = open file", i)
		}
		if _, err := os.Stat(want.outputPath); err != nil {
			t.Errorf("task %d output stat error: got = %v, want = nil", i, err)
		}
		c := task.Config
		if !slices.Equal(c.ScanPaths, []string{want.scanPath}) {
			t.Errorf("task %d scan paths: got = %v, want = [%s]", i, c.ScanPaths, want.scanPath)
		}
		if !slices.Equal(c.TrimPrefixes, []string{"pkg/action/"}) {
			t.Errorf("task %d trim prefixes: got = %v, want = [pkg/action/]", i, c.TrimPrefixes)
		}
		if got := c.Renderer.Name(); got != "JSON" {
			t.Errorf("task %d renderer: got = %q, want = %q", i, got, "JSON")
		}
		if c.Rules == nil {
			t.Errorf("task %d rules: got = nil, want = compiled rules", i)
		}
		if c.MinFileRisk != 0 || c.MinRisk != 0 {
			t.Errorf("task %d risk thresholds: got = %d/%d, want = 0/0", i, c.MinFileRisk, c.MinRisk)
		}
	}
}

func TestDiffRefreshBuildsDiffTasks(t *testing.T) {
	t.Parallel()
	samples := refreshDiffSamples(t)
	goldens := t.TempDir()

	tasks, err := diffRefresh(t.Context(), Config{SamplesPath: samples, TestDataPath: goldens})
	t.Cleanup(func() { closeTestDataFiles(tasks) })
	if err != nil {
		t.Fatalf("diffRefresh() error: got = %v, want = nil", err)
	}
	if len(tasks) != len(diffTestData) {
		t.Fatalf("task count: got = %d, want = %d", len(tasks), len(diffTestData))
	}
	byOutput := refreshByOutput(tasks)

	tests := []struct {
		name         string
		output       string
		src          string
		dest         string
		renderer     string
		minFileRisk  int
		minRisk      int
		riskChange   bool
		riskIncrease bool
	}{
		{"default thresholds", "macOS/2023.3CX/libffmpeg.dirty.mdiff", sampleDylib, sampleDirtyDylib, "Markdown", 1, 1, false, false},
		{"risk change filter", "macOS/2023.3CX/libffmpeg.change_increase.mdiff", sampleDylib, sampleDirtyDylib, "Markdown", 1, 1, true, false},
		{"risk increase filter", "macOS/2023.3CX/libffmpeg.decrease.mdiff", sampleDirtyDylib, sampleDylib, "Markdown", 1, 1, false, true},
		{"simple renderer", "linux/2024.sbcl.market/sbcl.sdiff", "linux/2024.sbcl.market/sbcl.clean", "linux/2024.sbcl.market/sbcl.dirty", "Simple", 1, 1, false, false},
		{"explicit file and overall thresholds", "macOS/clean/ls.sdiff.level_2", "linux/clean/ls.x86_64", sampleCleanLS, "Simple", 2, 2, false, false},
		{"explicit file threshold with default overall threshold", "macOS/clean/ls.sdiff.trigger_3", "linux/clean/ls.x86_64", sampleCleanLS, "Simple", 3, 1, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			task, ok := byOutput[filepath.Join(goldens, tt.output)]
			if !ok {
				t.Fatalf("task for %s: got = missing, want = present", tt.output)
			}
			if task.OutFile == nil {
				t.Error("output file: got = nil, want = open file")
			}
			if _, err := os.Stat(task.OutputPath); err != nil {
				t.Errorf("output stat error: got = %v, want = nil", err)
			}
			c := task.Config
			wantScan := []string{filepath.Join(samples, tt.src), filepath.Join(samples, tt.dest)}
			if !slices.Equal(c.ScanPaths, wantScan) {
				t.Errorf("scan paths: got = %v, want = %v", c.ScanPaths, wantScan)
			}
			if got := c.Renderer.Name(); got != tt.renderer {
				t.Errorf("renderer: got = %q, want = %q", got, tt.renderer)
			}
			if c.MinFileRisk != tt.minFileRisk {
				t.Errorf("MinFileRisk: got = %d, want = %d", c.MinFileRisk, tt.minFileRisk)
			}
			if c.MinRisk != tt.minRisk {
				t.Errorf("MinRisk: got = %d, want = %d", c.MinRisk, tt.minRisk)
			}
			if c.FileRiskChange != tt.riskChange {
				t.Errorf("FileRiskChange: got = %v, want = %v", c.FileRiskChange, tt.riskChange)
			}
			if c.FileRiskIncrease != tt.riskIncrease {
				t.Errorf("FileRiskIncrease: got = %v, want = %v", c.FileRiskIncrease, tt.riskIncrease)
			}
			if !slices.Equal(c.TrimPrefixes, []string{samples}) {
				t.Errorf("trim prefixes: got = %v, want = [%s]", c.TrimPrefixes, samples)
			}
		})
	}
}

func TestDiffRefreshReportsMissingSamples(t *testing.T) {
	t.Parallel()
	baseOnly := t.TempDir()
	refreshTouch(t, filepath.Join(baseOnly, sampleDylib))

	tests := []struct {
		name    string
		cancel  bool
		samples string
		wantMsg string
		wantIs  error
	}{
		{"canceled context", true, t.TempDir(), "", context.Canceled},
		{"missing base sample", false, t.TempDir(), "risk case base file not found", fs.ErrNotExist},
		{"missing compare sample", false, baseOnly, "risk case compare file not found", fs.ErrNotExist},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancel {
				cancel()
			}

			tasks, err := diffRefresh(ctx, Config{SamplesPath: tt.samples, TestDataPath: t.TempDir()})
			closeTestDataFiles(tasks)
			if !errors.Is(err, tt.wantIs) || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("diffRefresh() error: got = %v, want one matching %v and containing %q", err, tt.wantIs, tt.wantMsg)
			}
			if tasks != nil {
				t.Errorf("diffRefresh() tasks: got = %d, want = nil", len(tasks))
			}
		})
	}
}

func TestPrepareRefreshCollectsAllTasks(t *testing.T) {
	// Not parallel: actionRefresh resolves its inputs against the working
	// directory.
	root := t.TempDir()
	refreshActionInputs(t, root)
	samples := refreshDiffSamples(t)
	goldens := t.TempDir()

	sample := filepath.Join(samples, "linux/clean/hello")
	refreshTouch(t, sample)
	wantRenderers := map[string]string{
		"linux/clean/hello.simple": "Simple",
		"linux/clean/hello.md":     "Markdown",
		"linux/clean/hello.json":   "JSON",
	}
	for rel := range wantRenderers {
		refreshTouch(t, filepath.Join(goldens, rel))
	}
	t.Chdir(root)

	tasks, err := prepareRefresh(t.Context(), Config{SamplesPath: samples, TestDataPath: goldens, Concurrency: 1})
	t.Cleanup(func() { closeTestDataFiles(tasks) })
	if err != nil {
		t.Fatalf("prepareRefresh() error: got = %v, want = nil", err)
	}
	if want := len(actionTestData) + len(diffTestData) + len(wantRenderers); len(tasks) != want {
		t.Fatalf("task count: got = %d, want = %d", len(tasks), want)
	}

	byOutput := refreshByOutput(tasks)
	for rel, renderer := range wantRenderers {
		task, ok := byOutput[filepath.Join(goldens, rel)]
		if !ok {
			t.Errorf("task for %s: got = missing, want = present", rel)
			continue
		}
		c := task.Config
		if got := c.Renderer.Name(); got != renderer {
			t.Errorf("%s renderer: got = %q, want = %q", rel, got, renderer)
		}
		if !slices.Equal(c.ScanPaths, []string{sample}) {
			t.Errorf("%s scan paths: got = %v, want = [%s]", rel, c.ScanPaths, sample)
		}
		if !slices.Equal(c.TrimPrefixes, []string{samples}) {
			t.Errorf("%s trim prefixes: got = %v, want = [%s]", rel, c.TrimPrefixes, samples)
		}
		if c.MinFileRisk != 1 || c.MinRisk != 1 {
			t.Errorf("%s risk thresholds: got = %d/%d, want = 1/1", rel, c.MinFileRisk, c.MinRisk)
		}
		if c.Rules == nil {
			t.Errorf("%s rules: got = nil, want = compiled rules", rel)
		}
		if _, err := task.OutFile.WriteString("probe"); err != nil {
			t.Errorf("%s output file write: got error = %v, want = nil", rel, err)
		}
	}
}

func TestExecuteRefreshRendersAndClosesOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sample := filepath.Join(dir, "hello.sh")
	if err := os.WriteFile(sample, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", sample, err)
	}
	outPath := sample + ".simple"
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("Create(%q): %v", outPath, err)
	}
	t.Cleanup(func() { _ = out.Close() })

	r, err := render.New(formatSimple, out)
	if err != nil {
		t.Fatalf("render.New(%q): %v", formatSimple, err)
	}
	yrs, err := action.CachedRules(t.Context(), []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("CachedRules(): %v", err)
	}
	c := newConfig(Config{SamplesPath: dir})
	c.Renderer = r
	c.Rules = yrs
	c.ScanPaths = []string{sample}

	tasks := []TestData{{Config: c, OutFile: out, OutputPath: outPath}}
	if err := executeRefresh(t.Context(), Config{Concurrency: 1}, tasks, clog.FromContext(t.Context())); err != nil {
		t.Fatalf("executeRefresh() error: got = %v, want = nil", err)
	}
	if _, err := out.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Errorf("write after refresh: got error = %v, want = %v", err, os.ErrClosed)
	}
}

// refreshOpenFilesUnder counts this process's open file descriptors that refer
// to paths beneath dir. It reads /proc/self/fd and skips the test where that
// is unavailable.
func refreshOpenFilesUnder(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("open file descriptors are not listable: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, err)
	}
	prefix := resolved + string(filepath.Separator)
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && strings.HasPrefix(target, prefix) {
			n++
		}
	}
	return n
}

func TestDiffTestDataCoversEveryDiffGolden(t *testing.T) {
	t.Parallel()
	// Diff goldens are refreshed only through diffTestData, so every diff
	// golden checked in under tests/ needs an entry, and every entry needs a
	// golden.
	root := filepath.Join("..", "..", "tests")
	var got []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if name := d.Name(); strings.Contains(name, ".mdiff") || strings.Contains(name, ".sdiff") {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			got = append(got, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	want := make([]string, 0, len(diffTestData))
	for _, td := range diffTestData {
		want = append(want, td.outputPath)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("diff goldens under tests/: got = %v, want = %v (the diffTestData outputs)", got, want)
	}
}

func TestDiffRefreshClosesOpenedOutputsOnError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		setup   func(t *testing.T, samples, goldens string)
		wantErr string
	}{
		{
			name: "missing compare sample",
			setup: func(t *testing.T, samples, _ string) {
				t.Helper()
				// The first four cases compare only the two dylib samples; the
				// fifth needs the clean ls sample, which is missing.
				refreshTouch(t, filepath.Join(samples, sampleDylib))
				refreshTouch(t, filepath.Join(samples, sampleDirtyDylib))
			},
			wantErr: "risk case compare file not found",
		},
		{
			name: "output path taken by a directory",
			setup: func(t *testing.T, samples, goldens string) {
				t.Helper()
				for _, td := range diffTestData {
					refreshTouch(t, filepath.Join(samples, td.srcPath))
					refreshTouch(t, filepath.Join(samples, td.destPath))
				}
				// The second case cannot open its output after the first case
				// opened its own.
				if err := os.MkdirAll(filepath.Join(goldens, diffTestData[1].outputPath), 0o700); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
			},
			wantErr: "create output file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			samples := t.TempDir()
			goldens := t.TempDir()
			if n := refreshOpenFilesUnder(t, goldens); n != 0 {
				t.Fatalf("open files before refresh: got = %d, want = 0", n)
			}
			tt.setup(t, samples, goldens)

			tasks, err := diffRefresh(t.Context(), Config{SamplesPath: samples, TestDataPath: goldens})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("diffRefresh() error: got = %v, want one containing %q", err, tt.wantErr)
			}
			if tasks != nil {
				t.Errorf("diffRefresh() tasks: got = %d, want = nil", len(tasks))
			}
			if n := refreshOpenFilesUnder(t, goldens); n != 0 {
				t.Errorf("open output files after the error: got = %d, want = 0", n)
			}
		})
	}
}

func TestActionRefreshClosesOpenedOutputsOnError(t *testing.T) {
	// Not parallel: actionRefresh resolves its inputs against the working
	// directory.
	tests := []struct {
		name    string
		setup   func(t *testing.T, root string)
		wantErr string
	}{
		{
			name: "missing second input",
			setup: func(t *testing.T, root string) {
				t.Helper()
				refreshTouch(t, filepath.Join(root, actionTestData[0].scanPath))
			},
			wantErr: "special case input file not found",
		},
		{
			name: "second output path taken by a directory",
			setup: func(t *testing.T, root string) {
				t.Helper()
				refreshActionInputs(t, root)
				if err := os.MkdirAll(filepath.Join(root, actionTestData[1].outputPath), 0o700); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
			},
			wantErr: "create output file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if n := refreshOpenFilesUnder(t, root); n != 0 {
				t.Fatalf("open files before refresh: got = %d, want = 0", n)
			}
			// The second case fails after the first case opened its output.
			tt.setup(t, root)
			t.Chdir(root)

			tasks, err := actionRefresh(t.Context())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("actionRefresh() error: got = %v, want one containing %q", err, tt.wantErr)
			}
			if tasks != nil {
				t.Errorf("actionRefresh() tasks: got = %d, want = nil", len(tasks))
			}
			if n := refreshOpenFilesUnder(t, root); n != 0 {
				t.Errorf("open output files after the error: got = %d, want = 0", n)
			}
		})
	}
}

func TestPrepareRefreshClosesOpenedOutputsOnError(t *testing.T) {
	// Not parallel: actionRefresh resolves its inputs against the working
	// directory.
	tests := []struct {
		name    string
		setup   func(t *testing.T, goldens string)
		wantErr string
		wantIs  error
	}{
		{
			name: "golden that cannot be opened",
			setup: func(t *testing.T, goldens string) {
				t.Helper()
				// A golden that links into a missing directory is discovered
				// but cannot be opened for writing.
				golden := filepath.Join(goldens, "linux/clean/hello.simple")
				if err := os.MkdirAll(filepath.Dir(golden), 0o700); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				if err := os.Symlink(filepath.Join(goldens, "missing", "hello.simple"), golden); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			wantErr: "create output file",
			wantIs:  fs.ErrNotExist,
		},
		{
			name: "test data directory that cannot be walked",
			setup: func(t *testing.T, goldens string) {
				t.Helper()
				if os.Geteuid() == 0 {
					t.Skip("root reads directories regardless of their permissions")
				}
				locked := filepath.Join(goldens, "locked")
				if err := os.Mkdir(locked, 0o700); err != nil {
					t.Fatalf("Mkdir: %v", err)
				}
				if err := os.Chmod(locked, 0); err != nil {
					t.Fatalf("Chmod: %v", err)
				}
				t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
			},
			wantErr: "find test files",
			wantIs:  fs.ErrPermission,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Every action and diff output is open by the time discovery runs.
			root := t.TempDir()
			refreshActionInputs(t, root)
			samples := refreshDiffSamples(t)
			goldens := t.TempDir()
			refreshTouch(t, filepath.Join(samples, "linux/clean/hello"))
			tt.setup(t, goldens)
			t.Chdir(root)

			tasks, err := prepareRefresh(t.Context(), Config{SamplesPath: samples, TestDataPath: goldens, Concurrency: 1})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !errors.Is(err, tt.wantIs) {
				t.Fatalf("prepareRefresh() error: got = %v, want one containing %q and matching %v", err, tt.wantErr, tt.wantIs)
			}
			if tasks != nil {
				t.Errorf("prepareRefresh() tasks: got = %d, want = nil", len(tasks))
			}
			for _, dir := range []string{root, goldens} {
				if n := refreshOpenFilesUnder(t, dir); n != 0 {
					t.Errorf("open output files under %s after the error: got = %d, want = 0", dir, n)
				}
			}
		})
	}
}

// refreshCaptureStdout runs fn with os.Stdout redirected to a pipe and returns
// what fn printed. Callers must not run in parallel because os.Stdout is
// process-wide.
func refreshCaptureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	t.Cleanup(func() { os.Stdout = orig })

	os.Stdout = w
	fn()
	os.Stdout = orig

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	_ = r.Close()
	return string(out)
}

func TestExecuteRefreshReportsProgress(t *testing.T) {
	// Not parallel: os.Stdout is redirected to capture the progress lines.
	dir := t.TempDir()
	yrs, err := action.CachedRules(t.Context(), []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("CachedRules(): %v", err)
	}

	tasks := make([]TestData, 0, 2)
	for _, name := range []string{"first.sh", "second.sh"} {
		sample := filepath.Join(dir, name)
		if err := os.WriteFile(sample, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", sample, err)
		}
		outPath := sample + ".simple"
		out, err := os.Create(outPath)
		if err != nil {
			t.Fatalf("Create(%q): %v", outPath, err)
		}
		t.Cleanup(func() { _ = out.Close() })
		r, err := render.New(formatSimple, out)
		if err != nil {
			t.Fatalf("render.New(%q): %v", formatSimple, err)
		}
		c := newConfig(Config{SamplesPath: dir})
		c.Renderer = r
		c.Rules = yrs
		c.ScanPaths = []string{sample}
		tasks = append(tasks, TestData{Config: c, OutFile: out, OutputPath: outPath})
	}

	stdout := refreshCaptureStdout(t, func() {
		if err := executeRefresh(t.Context(), Config{Concurrency: 1}, tasks, clog.FromContext(t.Context())); err != nil {
			t.Errorf("executeRefresh() error: got = %v, want = nil", err)
		}
	})
	for _, want := range []string{
		"Sample data refreshed: 1/2",
		"Sample data refreshed: 2/2",
		"Successfully refreshed test data for 2 samples",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("progress output: got = %q, want it to contain %q", stdout, want)
		}
	}
}

func TestRefreshRunsWithNonPositiveConcurrency(t *testing.T) {
	// Not parallel: t.Setenv and t.Chdir affect the whole process.
	root := t.TempDir()
	refreshActionInputs(t, root)
	samples := refreshDiffSamples(t)
	goldens := t.TempDir()
	t.Setenv("MALCONTENT_UPX_PATH", refreshFakeUPX(t))
	t.Cleanup(release.ResetRuleURLRef)
	t.Chdir(root)

	// An errgroup limit of zero admits no goroutines, so Refresh must raise a
	// non-positive concurrency to one worker or its first task blocks forever.
	// Whatever scanning the empty stand-in inputs yields, Refresh returns and
	// every task closes its output file.
	err := Refresh(t.Context(), Config{SamplesPath: samples, TestDataPath: goldens, Concurrency: 0}, clog.FromContext(t.Context()))
	t.Logf("Refresh() with zero concurrency returned %v", err)

	for _, dir := range []string{root, goldens} {
		if n := refreshOpenFilesUnder(t, dir); n != 0 {
			t.Errorf("open output files under %s after Refresh: got = %d, want = 0", dir, n)
		}
	}
}
