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
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/release"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// refreshWriteFile writes data to path, creating its parent directories.
func refreshWriteFile(t *testing.T, path, data string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := file.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
	if err := file.WriteFileIn(dir, filepath.Base(path), []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

// refreshRoot opens a root on dir that stays open until the test ends.
func refreshRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot(%q): %v", dir, err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// refreshTouch creates an empty file at path along with its parent directories.
func refreshTouch(t *testing.T, path string) {
	t.Helper()
	refreshWriteFile(t, path, "")
}

// refreshActionInputs creates empty stand-ins for every pkg/action input
// beneath root. actionRefresh only checks that its inputs exist.
func refreshActionInputs(t *testing.T, root string) {
	t.Helper()
	for _, td := range actionTestData {
		refreshTouch(t, filepath.Join(root, td.scanPath))
	}
}

// refreshDiffInputs creates empty stand-ins for every diff source and
// destination beneath root. diffRefresh only checks that they exist.
func refreshDiffInputs(t *testing.T, root string) {
	t.Helper()
	for _, td := range diffTestData {
		refreshTouch(t, filepath.Join(root, td.srcPath))
		refreshTouch(t, filepath.Join(root, td.destPath))
	}
}

// refreshDiffSamples returns a samples directory holding empty stand-ins for
// every diff source and destination.
func refreshDiffSamples(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	refreshDiffInputs(t, root)
	return root
}

// refreshAllInputs creates stand-ins for every pkg/action input beneath root,
// for every diff sample beneath samples, and for the sample behind a
// linux/clean/hello golden.
func refreshAllInputs(t *testing.T, root, samples string) {
	t.Helper()
	refreshActionInputs(t, root)
	refreshDiffInputs(t, samples)
	refreshTouch(t, filepath.Join(samples, "linux/clean/hello"))
}

// refreshShellSample writes a small shell script to path and returns path.
func refreshShellSample(t *testing.T, path string) string {
	t.Helper()
	refreshWriteFile(t, path, "#!/bin/sh\necho hello\n")
	return path
}

// refreshUseActionTable replaces the pkg/action task table for the rest of
// the test. Callers must not run in parallel.
func refreshUseActionTable(t *testing.T, table []actionData) {
	t.Helper()
	orig := actionTestData
	t.Cleanup(func() { actionTestData = orig })
	actionTestData = table
}

// refreshUseDiffTable replaces the diff task table for the rest of the test.
// Callers must not run in parallel.
func refreshUseDiffTable(t *testing.T, table []diffData) {
	t.Helper()
	orig := diffTestData
	t.Cleanup(func() { diffTestData = orig })
	diffTestData = table
}

// refreshCancelingContext cancels itself the first time Err finds cond true.
// Refresh notices cancellation through Err, so this cancels a refresh at a
// chosen point in its work.
type refreshCancelingContext struct {
	context.Context
	cancel context.CancelFunc
	cond   func() bool
}

func (c refreshCancelingContext) Err() error {
	if c.cond() {
		c.cancel()
	}
	return c.Context.Err()
}

// refreshCancelWhen returns a context that is canceled once cond reports true
// during a call to its Err method.
func refreshCancelWhen(t *testing.T, cond func() bool) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return refreshCancelingContext{Context: ctx, cancel: cancel, cond: cond}
}

// refreshCancelOnceExists returns a context that is canceled once name exists
// beneath dir.
func refreshCancelOnceExists(t *testing.T, dir, name string) context.Context {
	t.Helper()
	return refreshCancelWhen(t, func() bool {
		_, err := file.StatIn(dir, name)
		return err == nil
	})
}

// refreshRecorder is a renderer that records the report passed to Full and
// returns fullErr from it.
type refreshRecorder struct {
	fullErr error
	calls   int
	report  *malcontent.Report
}

var _ malcontent.Renderer = (*refreshRecorder)(nil)

func (r *refreshRecorder) Scanning(context.Context, string) {}

func (r *refreshRecorder) File(context.Context, *malcontent.FileReport) error { return nil }

func (r *refreshRecorder) Full(_ context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	r.calls++
	r.report = rep
	return r.fullErr
}

func (r *refreshRecorder) Name() string { return "Recorder" }

// refreshRecorderTask returns a refresh task over paths, one path to scan or
// two to diff, that renders into rec.
func refreshRecorderTask(t *testing.T, rec *refreshRecorder, paths ...string) TestData {
	t.Helper()
	yrs, err := action.CachedRules(t.Context(), []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("CachedRules(): %v", err)
	}
	c := newConfig(Config{SamplesPath: filepath.Dir(paths[0])})
	c.Renderer = rec
	c.Rules = yrs
	c.ScanPaths = paths
	return TestData{Config: c, OutputPath: paths[len(paths)-1] + ".golden"}
}

// refreshCheckFailure checks that building refresh tasks returned no tasks and
// an error containing wantErr and, when wantIs is set, matching wantIs.
func refreshCheckFailure(t *testing.T, tasks []TestData, err error, wantErr string, wantIs error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Errorf("error: got = %v, want one containing %q", err, wantErr)
	}
	if wantIs != nil && !errors.Is(err, wantIs) {
		t.Errorf("error: got = %v, want one matching %v", err, wantIs)
	}
	if tasks != nil {
		t.Errorf("tasks: got = %d, want = nil", len(tasks))
	}
}

// refreshFakeUPX returns a regular, owner-only executable file that passes the
// MALCONTENT_UPX_PATH checks. Refresh validates the path but never runs it.
func refreshFakeUPX(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits required for the UPX path checks")
	}
	dir := t.TempDir()
	r := refreshRoot(t, dir)
	p := filepath.Join(dir, "upx")
	if err := r.WriteFile("upx", []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("WriteFile(%q): %v", p, err)
	}
	if err := r.Chmod("upx", 0o700); err != nil {
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
	if err := file.MkdirAllIn(goldens, "bundle.json", 0o700); err != nil {
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
		if _, err := file.StatIn(root, want.outputPath); err != nil {
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
		{"file threshold of two with default overall threshold", "macOS/clean/ls.sdiff.trigger_2", "linux/clean/ls.x86_64", sampleCleanLS, "Simple", 2, 1, false, false},
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
			if _, err := file.StatIn(goldens, tt.output); err != nil {
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
	if err := file.WriteFileIn(dir, "hello.sh", []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", sample, err)
	}
	outPath := sample + ".simple"
	out, err := file.OpenFileIn(dir, "hello.sh.simple", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
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
	fds, err := os.OpenRoot("/proc/self/fd")
	if err != nil {
		t.Skipf("open file descriptors are not listable: %v", err)
	}
	defer fds.Close()
	entries, err := fs.ReadDir(fds.FS(), ".")
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
		target, err := fds.Readlink(e.Name())
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
	err := fs.WalkDir(refreshRoot(t, root).FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if name := d.Name(); strings.Contains(name, ".mdiff") || strings.Contains(name, ".sdiff") {
			got = append(got, rel)
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
				if err := file.MkdirAllIn(goldens, diffTestData[1].outputPath, 0o700); err != nil {
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
				if err := file.MkdirAllIn(root, actionTestData[1].outputPath, 0o700); err != nil {
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
		name string
		// setup creates the pkg/action inputs under root, the samples, and
		// the goldens.
		setup func(t *testing.T, root, samples, goldens string)
		// ctx, when set, returns the context for the refresh.
		ctx     func(t *testing.T, goldens string) context.Context
		wantErr string
		wantIs  error
	}{
		{
			name: "missing action input",
			setup: func(t *testing.T, _, samples, _ string) {
				t.Helper()
				refreshDiffInputs(t, samples)
			},
			wantErr: "retrieve action tasks",
			wantIs:  fs.ErrNotExist,
		},
		{
			name: "missing diff sample after the action outputs opened",
			setup: func(t *testing.T, root, _, _ string) {
				t.Helper()
				refreshActionInputs(t, root)
			},
			wantErr: "retrieve risk tasks",
			wantIs:  fs.ErrNotExist,
		},
		{
			name: "golden that cannot be opened",
			setup: func(t *testing.T, root, samples, goldens string) {
				t.Helper()
				refreshAllInputs(t, root, samples)
				// A golden that links into a missing directory is discovered
				// but cannot be opened for writing.
				r := refreshRoot(t, goldens)
				if err := r.MkdirAll("linux/clean", 0o700); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				if err := r.Symlink(filepath.Join("missing", "hello.simple"), "linux/clean/hello.simple"); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			wantErr: "create output file",
			wantIs:  fs.ErrNotExist,
		},
		{
			name: "test data directory that cannot be walked",
			setup: func(t *testing.T, root, samples, goldens string) {
				t.Helper()
				if os.Geteuid() == 0 {
					t.Skip("root reads directories regardless of their permissions")
				}
				refreshAllInputs(t, root, samples)
				r := refreshRoot(t, goldens)
				if err := r.Mkdir("locked", 0o700); err != nil {
					t.Fatalf("Mkdir: %v", err)
				}
				if err := r.Chmod("locked", 0); err != nil {
					t.Fatalf("Chmod: %v", err)
				}
				t.Cleanup(func() { _ = r.Chmod("locked", 0o700) })
			},
			wantErr: "find test files",
			wantIs:  fs.ErrPermission,
		},
		{
			name: "canceled after opening a discovered golden",
			setup: func(t *testing.T, root, samples, goldens string) {
				t.Helper()
				refreshAllInputs(t, root, samples)
				refreshWriteFile(t, filepath.Join(goldens, "linux/clean/hello.simple"), "previous")
			},
			ctx: func(t *testing.T, goldens string) context.Context {
				t.Helper()
				// Opening a discovered golden truncates it, after every action
				// and diff output is already open.
				return refreshCancelWhen(t, func() bool {
					fi, err := file.StatIn(goldens, "linux/clean/hello.simple")
					return err == nil && fi.Size() == 0
				})
			},
			wantIs: context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			samples := t.TempDir()
			goldens := t.TempDir()
			tt.setup(t, root, samples, goldens)
			t.Chdir(root)
			ctx := t.Context()
			if tt.ctx != nil {
				ctx = tt.ctx(t, goldens)
			}

			tasks, err := prepareRefresh(ctx, Config{SamplesPath: samples, TestDataPath: goldens, Concurrency: 1})
			closeTestDataFiles(tasks)
			refreshCheckFailure(t, tasks, err, tt.wantErr, tt.wantIs)
			for _, dir := range []string{root, goldens} {
				if n := refreshOpenFilesUnder(t, dir); n != 0 {
					t.Errorf("open output files under %s after the error: got = %d, want = 0", dir, n)
				}
			}
		})
	}
}

func TestActionRefreshClosesOutputsWhenALaterTaskFails(t *testing.T) {
	// Not parallel: each case replaces the pkg/action task table.
	tests := []struct {
		name string
		// format and outDir configure the second task, which fails after the
		// first task opened its output.
		format string
		outDir string
		// blocked makes the second task's output directory a regular file.
		blocked bool
		// cancel cancels the refresh once the second task opened its output.
		cancel  bool
		wantErr string
		wantIs  error
	}{
		{name: "output directory taken by a file", format: formatJSON, outDir: "blocked", blocked: true, wantErr: "create output directory"},
		{name: "unknown output format", format: "unknown", outDir: "out", wantErr: "create renderer for"},
		{name: "canceled after opening the output", format: formatJSON, outDir: "out", cancel: true, wantIs: context.Canceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if n := refreshOpenFilesUnder(t, root); n != 0 {
				t.Fatalf("open files before refresh: got = %d, want = 0", n)
			}
			first := actionData{format: formatJSON, scanPath: filepath.Join(root, "in", "first"), outputPath: filepath.Join(root, "out", "first")}
			second := actionData{format: tt.format, scanPath: filepath.Join(root, "in", "second"), outputPath: filepath.Join(root, tt.outDir, "second")}
			refreshTouch(t, first.scanPath)
			refreshTouch(t, second.scanPath)
			if tt.blocked {
				refreshTouch(t, filepath.Dir(second.outputPath))
			}
			refreshUseActionTable(t, []actionData{first, second})
			ctx := t.Context()
			if tt.cancel {
				ctx = refreshCancelOnceExists(t, root, filepath.Join(tt.outDir, "second"))
			}

			tasks, err := actionRefresh(ctx)
			closeTestDataFiles(tasks)
			refreshCheckFailure(t, tasks, err, tt.wantErr, tt.wantIs)
			if _, err := file.StatIn(root, filepath.Join("out", "first")); err != nil {
				t.Errorf("first output stat error: got = %v, want = nil", err)
			}
			if n := refreshOpenFilesUnder(t, root); n != 0 {
				t.Errorf("open output files after the error: got = %d, want = 0", n)
			}
		})
	}
}

func TestDiffRefreshClosesOutputsWhenALaterTaskFails(t *testing.T) {
	// Not parallel: each case replaces the diff task table.
	tests := []struct {
		name string
		// src, format, and outDir configure the second task, which fails
		// after the first task opened its output.
		src    string
		format string
		outDir string
		// blocked makes the second task's output directory a regular file.
		blocked bool
		// cancel cancels the refresh once the second task opened its output.
		cancel  bool
		wantErr string
		wantIs  error
	}{
		{name: "missing base sample", src: "missing", format: formatSimple, outDir: "second", wantErr: "risk case base file not found", wantIs: fs.ErrNotExist},
		{name: "output directory taken by a file", src: "old", format: formatSimple, outDir: "blocked", blocked: true, wantErr: "create output directory"},
		{name: "unknown output format", src: "old", format: "unknown", outDir: "second", wantErr: "create renderer for"},
		{name: "canceled after opening the output", src: "old", format: formatSimple, outDir: "second", cancel: true, wantIs: context.Canceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			samples := t.TempDir()
			goldens := t.TempDir()
			if n := refreshOpenFilesUnder(t, goldens); n != 0 {
				t.Fatalf("open files before refresh: got = %d, want = 0", n)
			}
			refreshTouch(t, filepath.Join(samples, "old"))
			refreshTouch(t, filepath.Join(samples, "new"))
			first := diffData{srcPath: "old", destPath: "new", format: formatSimple, outputPath: filepath.Join("first", "out.sdiff")}
			second := diffData{srcPath: tt.src, destPath: "new", format: tt.format, outputPath: filepath.Join(tt.outDir, "out.sdiff")}
			if tt.blocked {
				refreshTouch(t, filepath.Join(goldens, tt.outDir))
			}
			refreshUseDiffTable(t, []diffData{first, second})
			ctx := t.Context()
			if tt.cancel {
				ctx = refreshCancelOnceExists(t, goldens, second.outputPath)
			}

			tasks, err := diffRefresh(ctx, Config{SamplesPath: samples, TestDataPath: goldens})
			closeTestDataFiles(tasks)
			refreshCheckFailure(t, tasks, err, tt.wantErr, tt.wantIs)
			if _, err := file.StatIn(goldens, first.outputPath); err != nil {
				t.Errorf("first output stat error: got = %v, want = nil", err)
			}
			if n := refreshOpenFilesUnder(t, goldens); n != 0 {
				t.Errorf("open output files after the error: got = %d, want = 0", n)
			}
		})
	}
}

func TestCanceledRefreshLeavesOutputsUntouched(t *testing.T) {
	// Not parallel: the task tables are replaced.
	root := t.TempDir()
	samples := t.TempDir()
	goldens := t.TempDir()

	scan := filepath.Join(root, "in", "scan")
	actionOut := filepath.Join(root, "out", "scan")
	refreshTouch(t, scan)
	refreshUseActionTable(t, []actionData{{format: formatJSON, scanPath: scan, outputPath: actionOut}})

	refreshTouch(t, filepath.Join(samples, "old"))
	refreshTouch(t, filepath.Join(samples, "new"))
	refreshUseDiffTable(t, []diffData{{srcPath: "old", destPath: "new", format: formatSimple, outputPath: "old.sdiff"}})

	refreshTouch(t, filepath.Join(samples, "hello"))
	outputs := []string{actionOut, filepath.Join(goldens, "old.sdiff"), filepath.Join(goldens, "hello.simple")}
	for _, out := range outputs {
		refreshWriteFile(t, out, "previous")
	}

	rc := Config{SamplesPath: samples, TestDataPath: goldens, Concurrency: 1}
	tests := []struct {
		name string
		run  func(ctx context.Context) ([]TestData, error)
	}{
		{name: "action tasks", run: actionRefresh},
		{name: "diff tasks", run: func(ctx context.Context) ([]TestData, error) { return diffRefresh(ctx, rc) }},
		{name: "all tasks", run: func(ctx context.Context) ([]TestData, error) { return prepareRefresh(ctx, rc) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			tasks, err := tt.run(ctx)
			closeTestDataFiles(tasks)
			refreshCheckFailure(t, tasks, err, "", context.Canceled)
			for _, out := range outputs {
				if got, err := file.ReadFileIn(filepath.Dir(out), filepath.Base(out)); err != nil || string(got) != "previous" {
					t.Errorf("%s after a canceled refresh: got = %q (read error %v), want = %q", out, got, err, "previous")
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
		if err := file.WriteFileIn(dir, name, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", sample, err)
		}
		outPath := sample + ".simple"
		out, err := file.OpenFileIn(dir, name+".simple", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
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

func TestExecuteRefreshRoutesTasks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	before := refreshShellSample(t, filepath.Join(dir, "before.sh"))
	after := refreshShellSample(t, filepath.Join(dir, "after.sh"))

	scanned, diffed := &refreshRecorder{}, &refreshRecorder{}
	tasks := []TestData{
		refreshRecorderTask(t, scanned, after),
		refreshRecorderTask(t, diffed, before, after),
	}
	if err := executeRefresh(t.Context(), Config{Concurrency: 2}, tasks, clog.FromContext(t.Context())); err != nil {
		t.Fatalf("executeRefresh() error: got = %v, want = nil", err)
	}

	tests := []struct {
		name     string
		rec      *refreshRecorder
		wantDiff bool
	}{
		{name: "one path is scanned", rec: scanned},
		{name: "two paths are diffed", rec: diffed, wantDiff: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.rec.calls != 1 {
				t.Fatalf("rendered reports: got = %d, want = 1", tt.rec.calls)
			}
			rep := tt.rec.report
			if rep == nil {
				t.Fatal("rendered report: got = nil, want = report")
			}
			// A diff reports changes; a scan reports per-file results.
			if got := rep.Diff != nil; got != tt.wantDiff {
				t.Errorf("report has diff: got = %v, want = %v", got, tt.wantDiff)
			}
			if got := rep.Files != nil; got == tt.wantDiff {
				t.Errorf("report has file results: got = %v, want = %v", got, !tt.wantDiff)
			}
		})
	}
}

func TestExecuteRefreshReportsTaskFailures(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sample := refreshShellSample(t, filepath.Join(dir, "hello.sh"))
	errRender := errors.New("render failed")

	tests := []struct {
		name string
		// paths and report configure the task: two paths with report set
		// diff two saved reports.
		paths     []string
		report    bool
		fullErr   error
		wantMsg   string
		wantIs    error
		wantCalls int
	}{
		{
			name:    "diff of a missing report",
			paths:   []string{filepath.Join(dir, "missing.json"), sample},
			report:  true,
			wantMsg: "refresh sample data for ",
			wantIs:  fs.ErrNotExist,
		},
		{
			name:      "render failure",
			paths:     []string{sample},
			fullErr:   errRender,
			wantMsg:   "render results for ",
			wantIs:    errRender,
			wantCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := &refreshRecorder{fullErr: tt.fullErr}
			task := refreshRecorderTask(t, rec, tt.paths...)
			task.Config.Report = tt.report

			err := executeRefresh(t.Context(), Config{Concurrency: 1}, []TestData{task}, clog.FromContext(t.Context()))
			if want := tt.wantMsg + task.OutputPath; err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("executeRefresh() error: got = %v, want one containing %q", err, want)
			}
			if !errors.Is(err, tt.wantIs) {
				t.Errorf("executeRefresh() error: got = %v, want one matching %v", err, tt.wantIs)
			}
			if rec.calls != tt.wantCalls {
				t.Errorf("rendered reports: got = %d, want = %d", rec.calls, tt.wantCalls)
			}
		})
	}
}

func TestExecuteRefreshRunsWithNonPositiveConcurrency(t *testing.T) {
	t.Parallel()
	// An errgroup limit of zero admits no goroutines, so a non-positive
	// concurrency must still run every task instead of blocking forever.
	sample := refreshShellSample(t, filepath.Join(t.TempDir(), "hello.sh"))

	tests := []struct {
		name        string
		concurrency int
	}{
		{name: "negative concurrency", concurrency: -1},
		{name: "zero concurrency", concurrency: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			first, second := &refreshRecorder{}, &refreshRecorder{}
			tasks := []TestData{refreshRecorderTask(t, first, sample), refreshRecorderTask(t, second, sample)}
			if err := executeRefresh(t.Context(), Config{Concurrency: tt.concurrency}, tasks, clog.FromContext(t.Context())); err != nil {
				t.Fatalf("executeRefresh() error: got = %v, want = nil", err)
			}
			for i, rec := range []*refreshRecorder{first, second} {
				if rec.calls != 1 {
					t.Errorf("task %d rendered reports: got = %d, want = 1", i, rec.calls)
				}
			}
		})
	}
}
