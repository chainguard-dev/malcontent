// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/action"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/release"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"github.com/urfave/cli/v3"
)

// errRender is the failure fakeRenderer returns from Full when asked to.
var errRender = errors.New("render failed")

// fakeRenderer counts Full calls and returns fullErr from them.
type fakeRenderer struct {
	name    string
	fullErr error
	full    int
}

func (r *fakeRenderer) Scanning(context.Context, string) {}

func (r *fakeRenderer) File(context.Context, *malcontent.FileReport) error { return nil }

func (r *fakeRenderer) Full(context.Context, *malcontent.Config, *malcontent.Report) error {
	r.full++
	return r.fullErr
}

func (r *fakeRenderer) Name() string { return r.name }

// newTestState returns CLI state that logs nowhere and writes its output to a
// file in a temporary directory instead of stdout.
func newTestState(t *testing.T) *cliState {
	t.Helper()
	out, err := file.OpenFileIn(t.TempDir(), "stdout", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create output file: %v", err)
	}
	t.Cleanup(func() { _ = out.Close() })
	return &cliState{
		log:      clog.New(slog.NewTextHandler(io.Discard, nil)),
		logLevel: new(slog.LevelVar),
		outFile:  out,
	}
}

// testContext returns a context carrying st's logger, canceled up front when
// canceled is true.
func testContext(t *testing.T, st *cliState, canceled bool) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(clog.WithLogger(t.Context(), st.log))
	t.Cleanup(cancel)
	if canceled {
		cancel()
	}
	return ctx
}

// neverMatchingRules compiles, once per test binary, a single rule that never
// matches. Sharing one rule set lets the action package keep reusing its
// scanner pool across tests instead of replacing it per test.
var neverMatchingRules = sync.OnceValues(func() (*yarax.Rules, error) {
	return yarax.Compile("rule mal_cli_test_never { condition: false }")
})

// scanReadyState returns CLI state prepared the way the Before stage leaves
// it, using neverMatchingRules instead of the full rule set and r as the
// renderer.
func scanReadyState(t *testing.T, r *fakeRenderer) *cliState {
	t.Helper()
	yrs, err := neverMatchingRules()
	if err != nil {
		t.Fatalf("compile test rule: %v", err)
	}

	st := newTestState(t)
	st.renderer = r
	st.mc = malcontent.Config{Concurrency: 1, Renderer: r, Rules: yrs}
	return st
}

// writeScript writes a small shell script into a temporary directory and
// returns its path.
func writeScript(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := file.WriteFileIn(dir, name, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// targetCommand returns a standalone analyze or scan command that runs run,
// so an Action can be exercised without the root command's Before stage.
func targetCommand(name string, run cli.ActionFunc) *cli.Command {
	return &cli.Command{Name: name, Flags: targetFlags(), Action: run}
}

func TestNewAppReportsVersion(t *testing.T) {
	// Not parallel: BuildVersion is a package variable.
	orig := BuildVersion
	t.Cleanup(func() { BuildVersion = orig })

	tests := []struct {
		name  string
		build string
		want  string
	}{
		{"unstamped build reports the release ID", "", release.ID},
		{"stamped build reports the stamped version", "v9.8.7", "v9.8.7"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BuildVersion = tt.build
			st := newTestState(t)
			app := newApp(st)
			var out bytes.Buffer
			app.Writer = &out

			if err := app.Run(testContext(t, st, false), []string{"mal", "--version"}); err != nil {
				t.Fatalf("Run(--version) error: got = %v, want = nil", err)
			}
			if got, want := out.String(), "malcontent version "+tt.want+"\n"; got != want {
				t.Errorf("--version output: got = %q, want = %q", got, want)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	t.Parallel()
	failure := errors.New("failure")
	matched := fmt.Errorf("scan: /tmp/x %w", action.ErrMatchedCondition)

	tests := []struct {
		name string
		code int
		err  error
		want int
	}{
		{"success", ExitOK, nil, ExitOK},
		{"failure without a recorded code", ExitOK, failure, ExitActionFailed},
		{"action failure", ExitActionFailed, failure, ExitActionFailed},
		{"invalid argument", ExitInvalidArgument, failure, ExitInvalidArgument},
		{"render failure", ExitRenderFailed, failure, ExitRenderFailed},
		{"input or output failure", ExitInputOutput, failure, ExitInputOutput},
		{"profiler failure", ExitProfilerError, failure, ExitProfilerError},
		{"invalid rules", ExitInvalidRules, failure, ExitInvalidRules},
		{"matched exit condition", ExitActionFailed, matched, ExitOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := exitCode(tt.code, tt.err); got != tt.want {
				t.Errorf("exitCode(%d, %v): got = %d, want = %d", tt.code, tt.err, got, tt.want)
			}
		})
	}
}

func TestResolveFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		format string
		args   []string
		want   string
	}{
		{"auto format for scan is brief", "auto", []string{"scan", "/bin"}, "terminal_brief"},
		{"auto format for analyze is full", "auto", []string{"analyze", "/bin"}, "terminal"},
		{"explicit format is kept for scan", "json", []string{"scan", "/bin"}, "json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveFormat(tt.format, tt.args); got != tt.want {
				t.Errorf("resolveFormat(%q, %v): got = %q, want = %q", tt.format, tt.args, got, tt.want)
			}
		})
	}
}

func TestRuleFS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		thirdParty bool
		want       []fs.FS
	}{
		{"first-party rules only", false, []fs.FS{rules.FS}},
		{"third-party rules added", true, []fs.FS{rules.FS, thirdparty.FS}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ruleFS(tt.thirdParty); !slices.Equal(got, tt.want) {
				t.Errorf("ruleFS(%v): got %d filesystems, want %d", tt.thirdParty, len(got), len(tt.want))
			}
		})
	}
}

func TestScanTargets(t *testing.T) {
	t.Parallel()
	images := []string{"cgr.dev/chainguard/static:latest"}
	args := []string{"/usr/bin"}

	tests := []struct {
		name          string
		images        []string
		processes     bool
		wantOCI       bool
		wantProcesses bool
		wantPaths     []string
	}{
		{"paths are scanned by default", nil, false, false, false, args},
		{"images select OCI scanning", images, false, true, false, images},
		{"images take precedence over processes", images, true, true, false, images},
		{"processes replace the path arguments", nil, true, false, true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var mc malcontent.Config
			scanTargets(&mc, tt.images, tt.processes, args)
			if mc.OCI != tt.wantOCI {
				t.Errorf("OCI: got = %v, want = %v", mc.OCI, tt.wantOCI)
			}
			if mc.Processes != tt.wantProcesses {
				t.Errorf("Processes: got = %v, want = %v", mc.Processes, tt.wantProcesses)
			}
			if !slices.Equal(mc.ScanPaths, tt.wantPaths) {
				t.Errorf("ScanPaths: got = %v, want = %v", mc.ScanPaths, tt.wantPaths)
			}
		})
	}
}

func TestShowAnalyzeHint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		renderer string
		files    int
		want     bool
	}{
		{"simple renderer with findings", "Simple", 1, true},
		{"terminal renderer with findings", "Terminal", 2, true},
		{"brief terminal renderer with findings", "TerminalBrief", 1, true},
		{"simple renderer without findings", "Simple", 0, false},
		{"brief terminal renderer without findings", "TerminalBrief", 0, false},
		{"JSON renderer with findings", "JSON", 1, false},
		{"markdown renderer with findings", "Markdown", 3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := showAnalyzeHint(tt.renderer, tt.files); got != tt.want {
				t.Errorf("showAnalyzeHint(%q, %d): got = %v, want = %v", tt.renderer, tt.files, got, tt.want)
			}
		})
	}
}

func TestGlobalFlagRiskAndFilterDefaults(t *testing.T) {
	// Not parallel: flag parsing writes package-level variables.
	cfg := parseGlobals(t, []string{"mal", "scan"})

	if minLevelFlag != -1 {
		t.Errorf("min-level default: got = %d, want = -1", minLevelFlag)
	}
	if minFileLevelFlag != -1 {
		t.Errorf("min-file-level default: got = %d, want = -1", minFileLevelFlag)
	}
	if formatFlag != "auto" {
		t.Errorf("format default: got = %q, want = %q", formatFlag, "auto")
	}
	if !thirdPartyFlag {
		t.Error("third-party default: got = false, want = true")
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"MinRisk", cfg.MinRisk, 1},
		{"MinFileRisk", cfg.MinFileRisk, 1},
		{"IgnoreSelf", cfg.IgnoreSelf, true},
		{"IncludeDataFiles", cfg.IncludeDataFiles, false},
		{"QuantityIncreasesRisk", cfg.QuantityIncreasesRisk, true},
		{"Concurrency", cfg.Concurrency, max(1, runtime.NumCPU())},
		{"MaxDepth", cfg.MaxDepth, 32},
		{"MaxScanFiles", cfg.MaxScanFiles, 1 << 21},
		{"MaxImageSize", cfg.MaxImageSize, int64(1 << 34)},
		{"Stats", cfg.Stats, false},
		{"darwin /private trim prefix", slices.Contains(cfg.TrimPrefixes, "/private"), runtime.GOOS == "darwin"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("default %s: got = %v, want = %v", tt.name, tt.got, tt.want)
		}
	}
	if want := []string{"false_positive", "ignore"}; !slices.Equal(cfg.IgnoreTags, want) {
		t.Errorf("default IgnoreTags: got = %v, want = %v", cfg.IgnoreTags, want)
	}
	if cfg.IgnoreRules != nil {
		t.Errorf("default IgnoreRules: got = %v, want = nil", cfg.IgnoreRules)
	}
}

func TestConfigFromFlags(t *testing.T) {
	// Not parallel: flag parsing writes package-level variables.
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, cfg malcontent.Config)
	}{
		{
			name: "named risk levels",
			args: []string{"mal", "--min-risk", "medium", "--min-file-risk", "crit", "scan"},
			check: func(t *testing.T, cfg malcontent.Config) {
				t.Helper()
				if cfg.MinRisk != 2 || cfg.MinFileRisk != 4 {
					t.Errorf("MinRisk/MinFileRisk: got = %d/%d, want = 2/4", cfg.MinRisk, cfg.MinFileRisk)
				}
			},
		},
		{
			name: "min-level overrides min-risk",
			args: []string{"mal", "--min-risk", "high", "--min-level", "0", "scan"},
			check: func(t *testing.T, cfg malcontent.Config) {
				t.Helper()
				if cfg.MinRisk != 0 {
					t.Errorf("MinRisk: got = %d, want = 0", cfg.MinRisk)
				}
			},
		},
		{
			name: "min-file-level overrides min-file-risk",
			args: []string{"mal", "--min-file-risk", "critical", "--min-file-level", "2", "scan"},
			check: func(t *testing.T, cfg malcontent.Config) {
				t.Helper()
				if cfg.MinFileRisk != 2 {
					t.Errorf("MinFileRisk: got = %d, want = 2", cfg.MinFileRisk)
				}
			},
		},
		{
			name: "custom ignore tags keep the default tags",
			args: []string{"mal", "--ignore-tags", "harmless", "scan"},
			check: func(t *testing.T, cfg malcontent.Config) {
				t.Helper()
				if want := []string{"harmless", "false_positive", "ignore"}; !slices.Equal(cfg.IgnoreTags, want) {
					t.Errorf("IgnoreTags: got = %v, want = %v", cfg.IgnoreTags, want)
				}
			},
		},
		{
			name: "default ignore tags are not repeated",
			args: []string{"mal", "--ignore-tags", "ignore,harmless", "scan"},
			check: func(t *testing.T, cfg malcontent.Config) {
				t.Helper()
				if want := []string{"ignore", "harmless", "false_positive"}; !slices.Equal(cfg.IgnoreTags, want) {
					t.Errorf("IgnoreTags: got = %v, want = %v", cfg.IgnoreTags, want)
				}
			},
		},
		{
			name: "ignore rules are split and trimmed",
			args: []string{"mal", "--ignore-rules", " py_lib_*, exfil_x ", "scan"},
			check: func(t *testing.T, cfg malcontent.Config) {
				t.Helper()
				if want := []string{"py_lib_*", "exfil_x"}; !slices.Equal(cfg.IgnoreRules, want) {
					t.Errorf("IgnoreRules: got = %v, want = %v", cfg.IgnoreRules, want)
				}
			},
		},
		{
			name: "all removes every filter",
			args: []string{"mal", "--all", "--ignore-rules", "py_lib_*", "--min-risk", "high", "--min-file-risk", "high", "scan"},
			check: func(t *testing.T, cfg malcontent.Config) {
				t.Helper()
				if cfg.IgnoreRules != nil {
					t.Errorf("IgnoreRules: got = %v, want = nil", cfg.IgnoreRules)
				}
				if cfg.IgnoreSelf {
					t.Error("IgnoreSelf: got = true, want = false")
				}
				if len(cfg.IgnoreTags) != 0 {
					t.Errorf("IgnoreTags: got = %v, want = none", cfg.IgnoreTags)
				}
				if !cfg.IncludeDataFiles {
					t.Error("IncludeDataFiles: got = false, want = true")
				}
				if cfg.MinRisk != -1 || cfg.MinFileRisk != -1 {
					t.Errorf("MinRisk/MinFileRisk: got = %d/%d, want = -1/-1", cfg.MinRisk, cfg.MinFileRisk)
				}
			},
		},
		{
			name: "zero jobs still runs one worker",
			args: []string{"mal", "--jobs", "0", "scan"},
			check: func(t *testing.T, cfg malcontent.Config) {
				t.Helper()
				if cfg.Concurrency != 1 {
					t.Errorf("Concurrency: got = %d, want = 1", cfg.Concurrency)
				}
			},
		},
		{
			name: "explicit jobs are kept",
			args: []string{"mal", "-j", "3", "scan"},
			check: func(t *testing.T, cfg malcontent.Config) {
				t.Helper()
				if cfg.Concurrency != 3 {
					t.Errorf("Concurrency: got = %d, want = 3", cfg.Concurrency)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, parseGlobals(t, tt.args))
		})
	}
}

func TestConfigFromFlagsRejectsInvalidValues(t *testing.T) {
	// Not parallel: flag parsing writes package-level variables.
	tests := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{"malformed ignore rule pattern", []string{"mal", "--ignore-rules", "[", "scan"}, "invalid --ignore-rules pattern"},
		{"unknown minimum risk", []string{"mal", "--min-risk", "severe", "scan"}, `unknown risk: "severe"`},
		{"unknown minimum file risk", []string{"mal", "--min-file-risk", "severe", "scan"}, `unknown risk: "severe"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseFlags(t, tt.args)
			_, err := configFromFlags()
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("configFromFlags() error: got = %v, want one containing %q", err, tt.wantMsg)
			}
		})
	}
}

func TestBeforeRejectsInvalidSettings(t *testing.T) {
	// Not parallel: flag parsing writes package-level variables.
	target := t.TempDir()
	unwritable := filepath.Join(t.TempDir(), "missing", "report.json")

	tests := []struct {
		name     string
		flags    []string
		wantCode int
		wantMsg  string
	}{
		{"malformed ignore rule pattern", []string{"--ignore-rules", "["}, ExitInvalidArgument, "invalid --ignore-rules pattern"},
		{"unknown minimum risk", []string{"--min-risk", "severe"}, ExitInvalidArgument, "unknown risk"},
		{"unknown minimum file risk", []string{"--min-file-risk", "severe"}, ExitInvalidArgument, "unknown risk"},
		{"unknown output format", []string{"--format", "sideways"}, ExitInvalidArgument, "unknown renderer"},
		{"unwritable output file", []string{"--output", unwritable}, ExitInputOutput, "report.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := newTestState(t)
			args := slices.Concat([]string{"mal"}, tt.flags, []string{"scan", target})

			err := newApp(st).Run(testContext(t, st, false), args)
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("Run(%v) error: got = %v, want one containing %q", args, err, tt.wantMsg)
			}
			if st.returnCode != tt.wantCode {
				t.Errorf("recorded code: got = %d, want = %d", st.returnCode, tt.wantCode)
			}
			if got := exitCode(st.returnCode, err); got != tt.wantCode {
				t.Errorf("exit code: got = %d, want = %d", got, tt.wantCode)
			}
			if st.mc.Scan {
				t.Error("scan command ran after a failed setup")
			}
			if _, err := st.outFile.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
				t.Errorf("output file after run: got write error = %v, want = %v", err, os.ErrClosed)
			}
		})
	}
}

func TestBeforeReportsProfilerFailure(t *testing.T) {
	// Not parallel: flag parsing writes package-level variables and the
	// profiler writes beneath the working directory.
	dir := t.TempDir()
	t.Chdir(dir)
	// A regular file where the profile directory belongs makes profiling fail.
	if err := file.WriteFileIn(dir, "profiles", nil, 0o600); err != nil {
		t.Fatalf("write profiles file: %v", err)
	}

	st := newTestState(t)
	err := newApp(st).Run(testContext(t, st, false), []string{"mal", "--profile", "scan", dir})
	if err == nil || !strings.Contains(err.Error(), "start profiling") {
		t.Fatalf("Run() error: got = %v, want a profiling failure", err)
	}
	if got := exitCode(st.returnCode, err); got != ExitProfilerError {
		t.Errorf("exit code: got = %d, want = %d", got, ExitProfilerError)
	}
	if st.profiler != nil {
		t.Error("profiler: got = running, want = nil after a failed start")
	}
}

func TestAnalyzeRendersRequestedReport(t *testing.T) {
	// Not parallel: flag parsing writes package-level variables. The Before
	// stage compiles the full rule set (served from the user cache when warm),
	// and the scan target is an empty temporary directory.
	target := t.TempDir()
	reportDir := t.TempDir()
	report := filepath.Join(reportDir, "report.json")
	st := newTestState(t)
	args := []string{
		"mal", "--format", "json", "--output", report, "--verbose",
		"--min-risk", "high", "--min-file-level", "2",
		"analyze", target,
	}

	if err := newApp(st).Run(testContext(t, st, false), args); err != nil {
		t.Fatalf("Run(%v) error: got = %v, want = nil", args, err)
	}
	if got := exitCode(st.returnCode, nil); got != ExitOK {
		t.Errorf("exit code: got = %d, want = %d", got, ExitOK)
	}
	if st.mc.Rules == nil {
		t.Error("rules: got = nil, want = compiled rules")
	}
	if got := st.renderer.Name(); got != "JSON" {
		t.Errorf("renderer: got = %q, want = %q", got, "JSON")
	}
	if st.mc.MinRisk != 3 || st.mc.MinFileRisk != 2 {
		t.Errorf("MinRisk/MinFileRisk: got = %d/%d, want = 3/2", st.mc.MinRisk, st.mc.MinFileRisk)
	}
	if !slices.Equal(st.mc.ScanPaths, []string{target}) {
		t.Errorf("ScanPaths: got = %v, want = [%s]", st.mc.ScanPaths, target)
	}
	if got := st.logLevel.Level(); got != slog.LevelDebug {
		t.Errorf("log level: got = %v, want = %v", got, slog.LevelDebug)
	}

	data, err := file.ReadFileIn(reportDir, "report.json")
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if len(data) == 0 || !json.Valid(data) {
		t.Errorf("report: got = %q, want a JSON document", data)
	}
	if _, err := st.outFile.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Errorf("report file after run: got write error = %v, want = %v", err, os.ErrClosed)
	}
}

func TestAnalyzeCommand(t *testing.T) {
	t.Parallel()
	script := writeScript(t, "hello.sh")

	tests := []struct {
		name      string
		args      []string
		canceled  bool
		renderErr error
		wantCode  int
		wantErr   error
		wantFull  int
	}{
		{"scan and render succeed", []string{"analyze", script}, false, nil, ExitOK, nil, 1},
		{"render failure", []string{"analyze", script}, false, errRender, ExitRenderFailed, errRender, 1},
		{"scan failure", []string{"analyze", script}, true, nil, ExitActionFailed, context.Canceled, 0},
		{"process lookup failure", []string{"analyze", "--processes"}, true, nil, ExitActionFailed, context.Canceled, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &fakeRenderer{name: "Terminal", fullErr: tt.renderErr}
			st := scanReadyState(t, r)

			err := targetCommand("analyze", st.analyze).Run(testContext(t, st, tt.canceled), tt.args)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("analyze error: got = %v, want = %v", err, tt.wantErr)
			}
			if st.returnCode != tt.wantCode {
				t.Errorf("recorded code: got = %d, want = %d", st.returnCode, tt.wantCode)
			}
			if r.full != tt.wantFull {
				t.Errorf("Full calls: got = %d, want = %d", r.full, tt.wantFull)
			}
		})
	}
}

func TestScanCommand(t *testing.T) {
	t.Parallel()
	script := writeScript(t, "hello.sh")

	tests := []struct {
		name      string
		renderer  string
		args      []string
		canceled  bool
		renderErr error
		wantCode  int
		wantErr   error
		wantMsg   string
		wantFull  int
	}{
		{"scan and render succeed", "Simple", []string{"scan", script}, false, nil, ExitOK, nil, "", 1},
		{"render failure", "Simple", []string{"scan", script}, false, errRender, ExitRenderFailed, errRender, "", 1},
		{"scan failure", "Simple", []string{"scan", script}, true, nil, ExitActionFailed, context.Canceled, "scan: ", 0},
		{"interactive renderer shows a failed scan", "Interactive", []string{"scan", script}, true, nil, ExitOK, nil, "", 1},
		{"process lookup failure", "Simple", []string{"scan", "--processes"}, true, nil, ExitActionFailed, context.Canceled, "process paths: ", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &fakeRenderer{name: tt.renderer, fullErr: tt.renderErr}
			st := scanReadyState(t, r)

			err := targetCommand("scan", st.scan).Run(testContext(t, st, tt.canceled), tt.args)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("scan error: got = %v, want = %v", err, tt.wantErr)
			}
			if err != nil && !strings.HasPrefix(err.Error(), tt.wantMsg) {
				t.Errorf("scan error: got = %q, want prefix %q", err, tt.wantMsg)
			}
			if st.returnCode != tt.wantCode {
				t.Errorf("recorded code: got = %d, want = %d", st.returnCode, tt.wantCode)
			}
			if r.full != tt.wantFull {
				t.Errorf("Full calls: got = %d, want = %d", r.full, tt.wantFull)
			}
			if !st.mc.Scan {
				t.Error("Scan mode: got = false, want = true")
			}
		})
	}
}

func TestDiffCommand(t *testing.T) {
	// Not parallel: the diff flags write package-level variables.
	src := writeScript(t, "before.sh")
	dest := writeScript(t, "after.sh")

	tests := []struct {
		name         string
		args         []string
		renderErr    error
		wantCode     int
		wantErr      string
		riskChange   bool
		riskIncrease bool
		sensitivity  int
		oci          bool
		report       bool
	}{
		{"default sensitivity applies no risk filter", []string{"diff", src}, nil, ExitActionFailed, "requires 2 paths", false, false, 5, false, false},
		{"sensitivity one shows only risk changes", []string{"diff", "--sensitivity", "1", src}, nil, ExitActionFailed, "requires 2 paths", true, false, 1, false, false},
		{"file risk change flag", []string{"diff", "--file-risk-change", src}, nil, ExitActionFailed, "requires 2 paths", true, false, 5, false, false},
		{"file risk increase flag", []string{"diff", "--file-risk-increase", src}, nil, ExitActionFailed, "requires 2 paths", false, true, 5, false, false},
		{"image and report flags", []string{"diff", "--image", "--report", src}, nil, ExitActionFailed, "requires 2 paths", false, false, 5, true, true},
		{"render failure", []string{"diff", src, dest}, errRender, ExitRenderFailed, errRender.Error(), false, false, 5, false, false},
		{"diff and render succeed", []string{"diff", src, dest}, nil, ExitOK, "", false, false, 5, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeRenderer{name: "Markdown", fullErr: tt.renderErr}
			st := scanReadyState(t, r)

			err := diffCommand(st).Run(testContext(t, st, false), tt.args)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("diff error: got = %v, want = nil", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("diff error: got = %v, want one containing %q", err, tt.wantErr)
			}
			if st.returnCode != tt.wantCode {
				t.Errorf("recorded code: got = %d, want = %d", st.returnCode, tt.wantCode)
			}
			mc := st.mc
			if mc.FileRiskChange != tt.riskChange || mc.FileRiskIncrease != tt.riskIncrease {
				t.Errorf("FileRiskChange/FileRiskIncrease: got = %v/%v, want = %v/%v",
					mc.FileRiskChange, mc.FileRiskIncrease, tt.riskChange, tt.riskIncrease)
			}
			if mc.Sensitivity != tt.sensitivity {
				t.Errorf("Sensitivity: got = %d, want = %d", mc.Sensitivity, tt.sensitivity)
			}
			if mc.OCI != tt.oci || mc.Report != tt.report {
				t.Errorf("OCI/Report: got = %v/%v, want = %v/%v", mc.OCI, mc.Report, tt.oci, tt.report)
			}
		})
	}
}

func TestRefreshTestDataReportsFailure(t *testing.T) {
	// Not parallel: t.Setenv controls UPX discovery for the whole process.
	t.Setenv("MALCONTENT_UPX_PATH", "bin/upx")
	t.Cleanup(release.ResetRuleURLRef)
	st := newTestState(t)

	err := st.refreshTestData(testContext(t, st, false), nil)
	if !errors.Is(err, programkind.ErrUPXPathInvalid) {
		t.Errorf("refresh error: got = %v, want = %v", err, programkind.ErrUPXPathInvalid)
	}
	if got := exitCode(st.returnCode, err); got != ExitInputOutput {
		t.Errorf("exit code: got = %d, want = %d", got, ExitInputOutput)
	}
}

func TestAwaitShutdown(t *testing.T) {
	t.Parallel()
	if drainTimeout != 10*time.Second {
		t.Errorf("drainTimeout: got = %v, want = %v", drainTimeout, 10*time.Second)
	}

	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM
	canceled := false
	exited := make(chan int, 1)
	logger := clog.New(slog.NewTextHandler(io.Discard, nil))

	awaitShutdown(sigCh, func() { canceled = true }, logger, time.Millisecond, func(code int) { exited <- code })

	if !canceled {
		t.Error("cancel after signal: got = not called, want = called")
	}
	if code := <-exited; code != 1 {
		t.Errorf("forced exit code: got = %d, want = 1", code)
	}
}

// malCaptureStderr runs fn with os.Stderr redirected to a pipe and returns
// what fn wrote there. Callers must not run in parallel because os.Stderr is
// process-wide.
func malCaptureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	t.Cleanup(func() { os.Stderr = orig })

	os.Stderr = w
	fn()
	os.Stderr = orig

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	_ = r.Close()
	return string(out)
}

func TestShowError(t *testing.T) {
	// Not parallel: os.Stderr is redirected.
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"failure", errors.New("scan failed"), "💣 scan failed\n"},
		{"matched exit condition", fmt.Errorf("/tmp/x %w", action.ErrMatchedCondition), "👋 /tmp/x matched exit criteria\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := malCaptureStderr(t, func() { showError(tt.err) }); got != tt.want {
				t.Errorf("showError output: got = %q, want = %q", got, tt.want)
			}
		})
	}
}
