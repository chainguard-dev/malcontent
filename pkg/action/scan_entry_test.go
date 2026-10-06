// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestScanMinFileRiskFilter(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	fx := newScanTestFixture(t, yrs, rfs)

	tests := []struct {
		name        string
		minFileRisk int
		wantKeys    []string
	}{
		{name: "zero minimum keeps every scanned file", minFileRisk: 0, wantKeys: []string{fx.clean, fx.hit}},
		{name: "minimum of one drops files without risk", minFileRisk: 1, wantKeys: []string{fx.hit}},
		{name: "minimum above every file drops all files", minFileRisk: fx.hitRisk + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := malcontent.Config{Concurrency: 2, MinFileRisk: tt.minFileRisk, Rules: yrs, RuleFS: rfs, ScanPaths: []string{fx.root}}

			r, err := Scan(t.Context(), c)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			want := slices.Sorted(slices.Values(tt.wantKeys))
			if got := scanTestKeys(r.Files); !slices.Equal(got, want) {
				t.Errorf("report keys: got = %v, want = %v", got, want)
			}
		})
	}
}

func TestScanMinFileRiskFilterAppliesToEmptyKeys(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	path, err := filepath.EvalSymlinks(scanTestWriteFile(t, filepath.Join(t.TempDir(), "locale.sh"), []byte(scanTestLocaleScript)))
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	// Trimming the whole scanned path leaves the file an empty report key.
	c := malcontent.Config{Concurrency: 1, MinFileRisk: 1, Rules: yrs, RuleFS: rfs, ScanPaths: []string{path}, TrimPrefixes: []string{path}}

	r, err := Scan(t.Context(), c)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := scanTestKeys(r.Files); len(got) != 0 {
		t.Errorf("report keys: got = %q, want none below the minimum file risk", got)
	}
}

func TestGetMaxConcurrencyWarnsOnlyWhenCapping(t *testing.T) {
	// Not parallel: replaces the package-level warning function.
	procs := runtime.GOMAXPROCS(0)
	tests := []struct {
		name       string
		configured int
		want       int
		wantWarn   bool
	}{
		{name: "value equal to GOMAXPROCS is used without a warning", configured: procs, want: procs},
		{name: "value above GOMAXPROCS is capped with a warning", configured: procs + 1, want: procs, wantWarn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warnings []string
			orig := concurrencyWarnf
			concurrencyWarnf = func(format string, args ...any) {
				warnings = append(warnings, fmt.Sprintf(format, args...))
			}
			t.Cleanup(func() { concurrencyWarnf = orig })

			if got := getMaxConcurrency(tt.configured); got != tt.want {
				t.Errorf("getMaxConcurrency(%d): got = %d, want = %d", tt.configured, got, tt.want)
			}
			if got := len(warnings) > 0; got != tt.wantWarn {
				t.Fatalf("cap warning logged: got = %t (%q), want = %t", got, warnings, tt.wantWarn)
			}
			if want := fmt.Sprintf("--jobs %d capped at %d", tt.configured, procs); tt.wantWarn && !strings.HasPrefix(warnings[0], want) {
				t.Errorf("cap warning: got = %q, want prefix %q", warnings[0], want)
			}
		})
	}
}

func TestScanUnresolvableScanPath(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	fx := newScanTestFixture(t, yrs, rfs)
	// A path below a regular file cannot be resolved.
	unresolvable := filepath.Join(fx.clean, "sub")

	tests := []struct {
		name        string
		scanPaths   []string
		interactive bool
		wantErr     error
		wantKeys    []string
	}{
		{name: "sole unresolvable scan path fails the scan", scanPaths: []string{unresolvable}, wantErr: syscall.ENOTDIR},
		{name: "unresolvable scan path among several is skipped", scanPaths: []string{unresolvable, fx.root}, wantKeys: []string{fx.clean, fx.hit}},
		{name: "interactive renderer keeps partial results instead of failing", scanPaths: []string{unresolvable}, interactive: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := malcontent.Config{Concurrency: 2, Rules: yrs, RuleFS: rfs, ScanPaths: tt.scanPaths}
			if tt.interactive {
				c.Renderer = &scanTestRenderer{name: "Interactive"}
			}

			r, err := Scan(t.Context(), c)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Scan error: got = %v, want = %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if r == nil {
				t.Fatal("report: got = nil, want = non-nil")
			}
			want := slices.Sorted(slices.Values(tt.wantKeys))
			if got := scanTestKeys(r.Files); !slices.Equal(got, want) {
				t.Errorf("report keys: got = %v, want = %v", got, want)
			}
		})
	}
}

func TestScanNotifiesRendererOfEachScanPath(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	first, second := t.TempDir(), t.TempDir()
	rnd := &scanTestRenderer{}
	c := malcontent.Config{Concurrency: 1, Renderer: rnd, Rules: yrs, RuleFS: rfs, ScanPaths: []string{first, second}}

	if _, err := Scan(t.Context(), c); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got, want := rnd.scanned(), []string{first, second}; !slices.Equal(got, want) {
		t.Errorf("scanning notifications: got = %v, want = %v", got, want)
	}
}

func TestScanCanceledMidScanReportsCancellation(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	root := t.TempDir()
	scanTestWriteFile(t, filepath.Join(root, "package.json"), readTestFile(t, scanTestNPMFixture))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Rendering happens after every per-file cancellation check, so canceling
	// there leaves only the scan-level check to notice.
	rnd := &scanTestRenderer{onFile: func(context.Context) { cancel() }}
	c := malcontent.Config{Concurrency: 1, Renderer: rnd, Rules: yrs, RuleFS: rfs, ScanPaths: []string{root}}

	_, err := Scan(ctx, c)
	if got := len(rnd.rendered()); got != 1 {
		t.Fatalf("fixture precondition: rendered reports: got = %d, want = 1", got)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Scan error: got = %v, want = %v", err, context.Canceled)
	}
}

// scanTestExpiringContext reports context.DeadlineExceeded once expire is
// called, standing in for a deadline that passes mid-scan.
type scanTestExpiringContext struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newScanTestExpiringContext(parent context.Context) *scanTestExpiringContext {
	return &scanTestExpiringContext{Context: parent, done: make(chan struct{})}
}

func (c *scanTestExpiringContext) Done() <-chan struct{} {
	return c.done
}

func (c *scanTestExpiringContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (c *scanTestExpiringContext) expire() {
	c.once.Do(func() { close(c.done) })
}

func TestScanDeadlineMidScanReportsIncompleteScan(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	root := t.TempDir()
	hit := scanTestWriteFile(t, filepath.Join(root, "package.json"), readTestFile(t, scanTestNPMFixture))

	ctx := newScanTestExpiringContext(t.Context())
	// The deadline passes while the only file renders. Waiting for the context
	// File received to end ensures every scan context has seen the deadline
	// before the file's worker returns.
	rnd := &scanTestRenderer{onFile: func(fileCtx context.Context) {
		ctx.expire()
		<-fileCtx.Done()
	}}
	c := malcontent.Config{Concurrency: 1, Renderer: rnd, Rules: yrs, RuleFS: rfs, ScanPaths: []string{root}}

	r, err := Scan(ctx, c)
	if got := len(rnd.rendered()); got != 1 {
		t.Fatalf("fixture precondition: rendered reports: got = %d, want = 1", got)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Scan error: got = %v, want = %v", err, context.DeadlineExceeded)
	}
	if r == nil {
		t.Fatal("partial report: got = nil, want = non-nil")
	}
	if got, want := scanTestKeys(r.Files), []string{hit}; !slices.Equal(got, want) {
		t.Errorf("partial report keys: got = %v, want = %v", got, want)
	}
}

func TestScanExitCriteriaReturnOnlyTheMatch(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	fx := newScanTestFixture(t, yrs, rfs)
	cleanRoot := t.TempDir()
	scanTestWriteFile(t, filepath.Join(cleanRoot, "locale.sh"), []byte(scanTestLocaleScript))

	tests := []struct {
		name         string
		root         string
		exitHit      bool
		exitMiss     bool
		wantKeys     []string
		wantRendered []string
	}{
		{name: "exit-first-hit returns and renders the hit as the only file", root: fx.root, exitHit: true, wantKeys: []string{fx.hit}, wantRendered: []string{fx.hit}},
		{name: "exit-first-miss returns no files", root: cleanRoot, exitMiss: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rnd := &scanTestRenderer{}
			c := malcontent.Config{
				Concurrency:   1,
				ExitFirstHit:  tt.exitHit,
				ExitFirstMiss: tt.exitMiss,
				Renderer:      rnd,
				Rules:         yrs,
				RuleFS:        rfs,
				ScanPaths:     []string{tt.root},
			}

			r, err := Scan(t.Context(), c)
			if !errors.Is(err, ErrMatchedCondition) || errors.Is(err, context.Canceled) {
				t.Fatalf("Scan error: got = %v, want = %v", err, ErrMatchedCondition)
			}
			if got := scanTestKeys(r.Files); !slices.Equal(got, tt.wantKeys) {
				t.Errorf("report keys: got = %v, want = %v", got, tt.wantKeys)
			}
			gotRendered := rnd.rendered()
			rendered := make([]string, 0, len(gotRendered))
			for _, fr := range gotRendered {
				rendered = append(rendered, fr.Path)
			}
			if !slices.Equal(rendered, tt.wantRendered) {
				t.Errorf("rendered paths: got = %v, want = %v", rendered, tt.wantRendered)
			}
		})
	}
}

func TestScanStatisticsOutput(t *testing.T) {
	// Not parallel: captures os.Stdout, where statistics are printed.
	yrs, rfs := scanTestRules(t)
	root := t.TempDir()
	scanTestWriteFile(t, filepath.Join(root, "locale.sh"), []byte(scanTestLocaleScript))

	tests := []struct {
		name       string
		stats      bool
		renderer   string
		noRenderer bool
		wantStats  bool
	}{
		{name: "statistics print for terminal output", stats: true, renderer: "Terminal", wantStats: true},
		{name: "statistics are omitted for JSON output", stats: true, renderer: "JSON"},
		{name: "statistics are omitted for YAML output", stats: true, renderer: "YAML"},
		{name: "statistics are omitted when not requested", renderer: "Terminal"},
		{name: "statistics are omitted without a renderer", stats: true, noRenderer: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := malcontent.Config{
				Concurrency: 1,
				Renderer:    &scanTestRenderer{name: tt.renderer},
				Rules:       yrs,
				RuleFS:      rfs,
				ScanPaths:   []string{root},
				Stats:       tt.stats,
			}
			if tt.noRenderer {
				c.Renderer = nil
			}

			var scanErr error
			out := scanTestCaptureStdout(t, func() {
				_, scanErr = Scan(t.Context(), c)
			})
			if scanErr != nil {
				t.Fatalf("Scan: %v", scanErr)
			}
			if got := strings.Contains(out, "Files Scanned"); got != tt.wantStats {
				t.Errorf("statistics printed: got = %t, want = %t (stdout: %q)", got, tt.wantStats, out)
			}
		})
	}
}
