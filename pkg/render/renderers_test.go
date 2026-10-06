// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/puzpuzpuz/xsync/v4"
)

type renderTextRenderer struct {
	name         string
	newRenderer  func(io.Writer) malcontent.Renderer
	echoScanning bool
}

// renderTextRenderers lists the human-readable renderers that stream file reports.
func renderTextRenderers() []renderTextRenderer {
	return []renderTextRenderer{
		{name: "terminal", newRenderer: func(w io.Writer) malcontent.Renderer { return NewTerminal(w) }, echoScanning: true},
		{name: "terminal_brief", newRenderer: func(w io.Writer) malcontent.Renderer { return NewTerminalBrief(w) }, echoScanning: true},
		{name: "strings", newRenderer: func(w io.Writer) malcontent.Renderer { return NewStringMatches(w) }, echoScanning: true},
		{name: "markdown", newRenderer: func(w io.Writer) malcontent.Renderer { return NewMarkdown(w) }},
		{name: "simple", newRenderer: func(w io.Writer) malcontent.Renderer { return NewSimple(w) }},
	}
}

// renderBehaviorReport returns a scan report with one behavior that every renderer displays.
func renderBehaviorReport() *malcontent.FileReport {
	return &malcontent.FileReport{
		Path:      "/bin/tool",
		RiskScore: 3,
		RiskLevel: report.LevelHIGH,
		Behaviors: []*malcontent.Behavior{{
			ID:           "net/connect",
			Description:  "connects to hosts",
			MatchStrings: []string{"AF_INET"},
			RiskScore:    3,
			RiskLevel:    report.LevelHIGH,
			RuleName:     "net_connect",
		}},
	}
}

func TestTextRenderersFullWithoutDiffWriteNothing(t *testing.T) {
	t.Parallel()
	reports := []struct {
		name string
		rep  *malcontent.Report
	}{
		{name: "nil report", rep: nil},
		{name: "scan report without diff", rep: &malcontent.Report{Files: xsync.NewMap[string, *malcontent.FileReport]()}},
	}
	for _, r := range renderTextRenderers() {
		for _, tt := range reports {
			t.Run(r.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				var buf bytes.Buffer
				if err := r.newRenderer(&buf).Full(t.Context(), &malcontent.Config{}, tt.rep); err != nil {
					t.Fatalf("Full: got err = %v, want = nil", err)
				}
				if buf.Len() != 0 {
					t.Errorf("Full output: got = %q, want = empty", buf.String())
				}
			})
		}
	}
}

func TestTextRenderersHonorCanceledContext(t *testing.T) {
	t.Parallel()
	for _, r := range renderTextRenderers() {
		t.Run(r.name+"/File", func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := r.newRenderer(&buf).File(renderCanceledContext(t), renderBehaviorReport())
			if !errors.Is(err, context.Canceled) {
				t.Errorf("File error: got = %v, want = %v", err, context.Canceled)
			}
			if buf.Len() != 0 {
				t.Errorf("File output: got = %q, want = empty", buf.String())
			}
		})
		t.Run(r.name+"/Full", func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			rep := &malcontent.Report{Diff: renderDiff(nil, []*malcontent.FileReport{renderBehaviorReport()}, nil)}
			err := r.newRenderer(&buf).Full(renderCanceledContext(t), &malcontent.Config{}, rep)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Full error: got = %v, want = %v", err, context.Canceled)
			}
			if buf.Len() != 0 {
				t.Errorf("Full output: got = %q, want = empty", buf.String())
			}
		})
		// The cancellation is reported even when there is nothing to render.
		t.Run(r.name+"/Full without a report", func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := r.newRenderer(&buf).Full(renderCanceledContext(t), &malcontent.Config{}, nil)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Full error: got = %v, want = %v", err, context.Canceled)
			}
			if buf.Len() != 0 {
				t.Errorf("Full output: got = %q, want = empty", buf.String())
			}
		})
	}
}

func TestTextRenderersFileIgnoresSkippedAndEmptyReports(t *testing.T) {
	t.Parallel()
	reports := []struct {
		name string
		fr   *malcontent.FileReport
	}{
		{
			name: "skipped report with behaviors",
			fr: &malcontent.FileReport{
				Path:      "/bin/skipped",
				Skipped:   "data file",
				RiskScore: 3,
				RiskLevel: report.LevelHIGH,
				Behaviors: renderBehaviorReport().Behaviors,
			},
		},
		{name: "report without behaviors", fr: &malcontent.FileReport{Path: "/bin/empty"}},
		{name: "moved report without behaviors", fr: &malcontent.FileReport{Path: "/bin/empty", PreviousPath: "/bin/old", PreviousRelPath: "bin/old"}},
	}
	for _, r := range renderTextRenderers() {
		for _, tt := range reports {
			t.Run(r.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				var buf bytes.Buffer
				if err := r.newRenderer(&buf).File(t.Context(), tt.fr); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				if buf.Len() != 0 {
					t.Errorf("File output: got = %q, want = empty", buf.String())
				}
			})
		}
	}
}

func TestTextRenderersScanningQuotesPath(t *testing.T) {
	t.Parallel()
	// Control characters in a scanned path must not reach the terminal raw.
	const path = "/tmp/evil\x1b[2J\nname"
	for _, r := range renderTextRenderers() {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			r.newRenderer(&buf).Scanning(t.Context(), path)
			want := ""
			if r.echoScanning {
				want = "🔎 Scanning " + strconv.Quote(path) + "\n"
			}
			if got := buf.String(); got != want {
				t.Errorf("Scanning output: got = %q, want = %q", got, want)
			}
			if strings.ContainsRune(buf.String(), '\x1b') {
				t.Errorf("Scanning output: got raw escape byte in %q, want = none", buf.String())
			}
		})
	}
}

func TestSanitizeUTF8BiDiRangeBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		r     rune
		strip bool
	}{
		{name: "paragraph separator below LRE is kept", r: ' '},
		{name: "LRE is stripped", r: '‪', strip: true},
		{name: "RLO is stripped", r: '‮', strip: true},
		{name: "narrow no-break space above RLO is kept", r: ' '},
		{name: "code point below LRI is kept", r: '⁥'},
		{name: "LRI is stripped", r: '⁦', strip: true},
		{name: "PDI is stripped", r: '⁩', strip: true},
		{name: "code point above PDI is kept", r: '⁪'},
		{name: "zero-width joiner below LRM is kept", r: '‍'},
		{name: "LRM is stripped", r: '‎', strip: true},
		{name: "RLM is stripped", r: '‏', strip: true},
		{name: "hyphen above RLM is kept", r: '‐'},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := "a" + string(tt.r) + "b"
			want := in
			if tt.strip {
				want = "ab"
			}
			if got := sanitizeUTF8(in); got != want {
				t.Errorf("sanitizeUTF8(%q): got = %q, want = %q", in, got, want)
			}
		})
	}
}

func TestFullStopsAtTheFirstFailedWrite(t *testing.T) {
	t.Parallel()
	behavior := func(id string, added bool) []*malcontent.Behavior {
		return []*malcontent.Behavior{{ID: id, Description: "does things", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: added}}
	}
	// diff has one deleted, one added, and one changed file: three sections.
	diff := func() *malcontent.Report {
		return &malcontent.Report{Diff: renderDiff(
			[]*malcontent.FileReport{{Path: "/old/tool", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: behavior("net/connect", false)}},
			[]*malcontent.FileReport{{Path: "/new/tool", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: behavior("fs/write", false)}},
			[]*malcontent.FileReport{{Path: "/mod/tool", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: behavior("exec/shell", true)}},
		)}
	}
	// scan has 33 small files: one more than a JSON chunk holds.
	scan := func() *malcontent.Report {
		files := xsync.NewMap[string, *malcontent.FileReport]()
		for i := range 33 {
			key := fmt.Sprintf("/f/%02d", i)
			files.Store(key, &malcontent.FileReport{Path: key})
		}
		return &malcontent.Report{Files: files}
	}
	tests := []struct {
		name   string
		full   func(context.Context, io.Writer) error
		writes int
	}{
		{name: "terminal writes each section", full: func(ctx context.Context, w io.Writer) error {
			return NewTerminal(w).Full(ctx, &malcontent.Config{}, diff())
		}, writes: 3},
		{name: "simple writes each section", full: func(ctx context.Context, w io.Writer) error {
			return NewSimple(w).Full(ctx, &malcontent.Config{}, diff())
		}, writes: 3},
		{name: "markdown writes each section", full: func(ctx context.Context, w io.Writer) error {
			return NewMarkdown(w).Full(ctx, &malcontent.Config{}, diff())
		}, writes: 3},
		{name: "json writes the opening, two chunks, and the closing", full: func(ctx context.Context, w io.Writer) error { return NewJSON(w).Full(ctx, nil, scan()) }, writes: 4},
		{name: "yaml writes its buffer once", full: func(ctx context.Context, w io.Writer) error { return NewYAML(w).Full(ctx, nil, scan()) }, writes: 1},
	}
	for _, tt := range tests {
		// failAt 0 lets every write succeed.
		for failAt := range tt.writes + 1 {
			name := tt.name + "/every write succeeds"
			if failAt > 0 {
				name = fmt.Sprintf("%s/write %d fails", tt.name, failAt)
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				w := &renderWriteLog{failAt: failAt}
				err := tt.full(t.Context(), w)
				var wantErr error
				wantWrites := tt.writes
				if failAt > 0 {
					wantErr, wantWrites = errRenderWrite, failAt
				}
				if !errors.Is(err, wantErr) {
					t.Errorf("Full error: got = %v, want = %v", err, wantErr)
				}
				if len(w.writes) != wantWrites {
					t.Errorf("writes: got = %d, want = %d", len(w.writes), wantWrites)
				}
			})
		}
	}
}
