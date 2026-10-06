// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// teaUpdate applies msg to m and returns the updated model and command.
func teaUpdate(t *testing.T, m mainModel, msg tea.Msg) (mainModel, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(msg)
	got, ok := next.(mainModel)
	if !ok {
		t.Fatalf("Update model: got = %T, want = mainModel", next)
	}
	return got, cmd
}

// teaReadyModel returns a model that has received a 100x30 window size and the given results.
func teaReadyModel(t *testing.T, results ...string) mainModel {
	t.Helper()
	m, _ := teaUpdate(t, newMainModel(), tea.WindowSizeMsg{Width: 100, Height: 30})
	for _, r := range results {
		m, _ = teaUpdate(t, m, resultUpdateMsg{content: r, isResult: true})
	}
	return m
}

// teaKeys sends each key to m in order.
func teaKeys(t *testing.T, m mainModel, keys ...tea.KeyMsg) mainModel {
	t.Helper()
	for _, k := range keys {
		m, _ = teaUpdate(t, m, k)
	}
	return m
}

func teaRunes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// teaVisible returns the viewport text without styling.
func teaVisible(m mainModel) string {
	return renderStripANSI(m.viewport.View())
}

func TestNewMainModelSpinner(t *testing.T) {
	t.Parallel()
	m := newMainModel()
	if got, want := m.spinner.Spinner.FPS, 250*time.Millisecond; got != want {
		t.Errorf("spinner FPS: got = %v, want = %v", got, want)
	}
	if want := []string{"🔍", "🔎"}; !slices.Equal(m.spinner.Spinner.Frames, want) {
		t.Errorf("spinner frames: got = %q, want = %q", m.spinner.Spinner.Frames, want)
	}
	if m.ready || m.quitting || m.searchMode || len(m.content) != 0 {
		t.Errorf("new model state: got ready=%v quitting=%v searchMode=%v content=%q, want all unset", m.ready, m.quitting, m.searchMode, m.content)
	}
}

func TestMainModelWindowSize(t *testing.T) {
	t.Parallel()
	m, _ := teaUpdate(t, newMainModel(), resultUpdateMsg{content: "found before sizing", isResult: true})

	m, _ = teaUpdate(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	if !m.ready {
		t.Fatal("ready after first window size: got = false, want = true")
	}
	// The viewport leaves room for a 4-column border and 5 lines of header and footer.
	if m.viewport.Width != 96 || m.viewport.Height != 25 {
		t.Errorf("viewport size: got = %dx%d, want = 96x25", m.viewport.Width, m.viewport.Height)
	}
	if m.width != 100 || m.height != 30 {
		t.Errorf("window size: got = %dx%d, want = 100x30", m.width, m.height)
	}
	if got := teaVisible(m); !strings.Contains(got, "found before sizing") {
		t.Errorf("viewport content: got = %q, want earlier results", got)
	}

	m, _ = teaUpdate(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	if m.viewport.Width != 116 || m.viewport.Height != 35 {
		t.Errorf("resized viewport: got = %dx%d, want = 116x35", m.viewport.Width, m.viewport.Height)
	}
	if m.width != 120 || m.height != 40 {
		t.Errorf("resized window: got = %dx%d, want = 120x40", m.width, m.height)
	}
	if got := teaVisible(m); !strings.Contains(got, "found before sizing") {
		t.Errorf("resized viewport content: got = %q, want earlier results", got)
	}
}

func TestMainModelResultUpdates(t *testing.T) {
	t.Parallel()
	m := teaReadyModel(t)
	updates := []resultUpdateMsg{
		{content: "first finding", isResult: true},
		{content: "  context line  ", isResult: false},
		{content: "skipped /tmp/x: data file", isResult: false},
		{content: "open /root: permission denied", isResult: true},
	}
	for _, u := range updates {
		m, _ = teaUpdate(t, m, u)
	}

	if want := []string{"first finding", "context line"}; !slices.Equal(m.content, want) {
		t.Errorf("content: got = %q, want = %q", m.content, want)
	}
	if want := []string{"skipped /tmp/x: data file", "open /root: permission denied"}; !slices.Equal(m.errors, want) {
		t.Errorf("errors: got = %q, want = %q", m.errors, want)
	}
	if m.resultCount != 1 {
		t.Errorf("result count: got = %d, want = 1", m.resultCount)
	}
	if got := m.viewport.TotalLineCount(); got != 2 {
		t.Errorf("viewport lines: got = %d, want = 2", got)
	}
	if got := renderStripANSI(m.View()); !strings.Contains(got, "Found 1 results") {
		t.Errorf("footer: got = %q, want = Found 1 results", got)
	}
}

func TestMainModelScanStatus(t *testing.T) {
	t.Parallel()
	m := teaReadyModel(t)

	m, cmd := teaUpdate(t, m, scanUpdateMsg{path: "/bin/scanning-now"})
	if cmd != nil {
		t.Error("scan update command: got = non-nil, want = nil")
	}
	if got := renderStripANSI(m.View()); !strings.Contains(got, "Scanning: /bin/scanning-now") {
		t.Errorf("view during scan: got = %q, want scanning status", got)
	}

	m, _ = teaUpdate(t, m, scanCompleteMsg{})
	if got := renderStripANSI(m.View()); strings.Contains(got, "Scanning:") {
		t.Errorf("view after scan: got = %q, want no scanning status", got)
	}
}

func TestMainModelQuitKeys(t *testing.T) {
	t.Parallel()
	for _, k := range []tea.KeyMsg{teaRunes("q"), {Type: tea.KeyCtrlC}, {Type: tea.KeyEsc}} {
		t.Run(k.String(), func(t *testing.T) {
			t.Parallel()
			m, cmd := teaUpdate(t, teaReadyModel(t), k)
			if !m.quitting {
				t.Error("quitting: got = false, want = true")
			}
			if cmd == nil {
				t.Fatal("command: got = nil, want = quit")
			}
			if _, ok := cmd().(tea.QuitMsg); !ok {
				t.Errorf("command message: got = %T, want = tea.QuitMsg", cmd())
			}
		})
	}
}

func TestMainModelHomeAndEndKeys(t *testing.T) {
	t.Parallel()
	lines := make([]string, 0, 60)
	for i := range 60 {
		lines = append(lines, strings.Repeat("x", i%10+1))
	}
	m := teaReadyModel(t, lines...)
	if !m.viewport.AtBottom() {
		t.Fatal("viewport after new results: got = not at bottom, want = at bottom")
	}
	m = teaKeys(t, m, tea.KeyMsg{Type: tea.KeyHome})
	if !m.viewport.AtTop() {
		t.Errorf("viewport after home: got offset %d, want = top", m.viewport.YOffset)
	}
	m = teaKeys(t, m, tea.KeyMsg{Type: tea.KeyEnd})
	if !m.viewport.AtBottom() {
		t.Errorf("viewport after end: got offset %d, want = bottom", m.viewport.YOffset)
	}
}

func TestMainModelScrollKeysMoveOnce(t *testing.T) {
	t.Parallel()
	// A 30-line window leaves a 25-line viewport, so half a page is 12 lines.
	const (
		page     = 25
		halfPage = 12
	)
	lines := make([]string, 0, 100)
	for i := range 100 {
		lines = append(lines, strings.Repeat("x", i%10+1))
	}
	home := tea.KeyMsg{Type: tea.KeyHome}
	end := tea.KeyMsg{Type: tea.KeyEnd}
	tests := []struct {
		name      string
		start     tea.KeyMsg
		key       tea.KeyMsg
		wantDelta int
	}{
		{name: "down arrow scrolls one line", start: home, key: tea.KeyMsg{Type: tea.KeyDown}, wantDelta: 1},
		{name: "j scrolls one line", start: home, key: teaRunes("j"), wantDelta: 1},
		{name: "page down scrolls half a page", start: home, key: tea.KeyMsg{Type: tea.KeyPgDown}, wantDelta: halfPage},
		{name: "up arrow scrolls one line", start: end, key: tea.KeyMsg{Type: tea.KeyUp}, wantDelta: -1},
		{name: "k scrolls one line", start: end, key: teaRunes("k"), wantDelta: -1},
		{name: "page up scrolls half a page", start: end, key: tea.KeyMsg{Type: tea.KeyPgUp}, wantDelta: -halfPage},
		{name: "viewport binding f still scrolls a full page", start: home, key: teaRunes("f"), wantDelta: page},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := teaKeys(t, teaReadyModel(t, lines...), tt.start)
			before := m.viewport.YOffset
			if tt.start.Type == tea.KeyEnd && before < page {
				t.Fatalf("bottom offset: got = %d, want >= %d", before, page)
			}
			m = teaKeys(t, m, tt.key)
			if got := m.viewport.YOffset - before; got != tt.wantDelta {
				t.Errorf("offset change after one %q press: got = %d, want = %d", tt.key.String(), got, tt.wantDelta)
			}
		})
	}
}

func TestMainModelSearch(t *testing.T) {
	t.Parallel()
	results := []string{"alpha one", "beta two", "gamma three", "Alpha four"}
	m := teaReadyModel(t, results...)

	m = teaKeys(t, m, teaRunes("/"))
	if !m.searchMode || m.searchTerm != "" {
		t.Fatalf("after slash: got searchMode=%v term=%q, want searchMode=true term=\"\"", m.searchMode, m.searchTerm)
	}

	// Backspace on an empty term and multi-character keys leave the term alone.
	m = teaKeys(t, m, tea.KeyMsg{Type: tea.KeyBackspace}, teaRunes("a"), teaRunes("l"), tea.KeyMsg{Type: tea.KeyTab}, teaRunes("p"), teaRunes("h"), teaRunes("a"))
	if m.searchTerm != "alpha" {
		t.Errorf("search term: got = %q, want = %q", m.searchTerm, "alpha")
	}
	// Matching is case-insensitive, and the line after each match is kept for context.
	got := teaVisible(m)
	for _, want := range []string{"alpha one", "beta two", "Alpha four"} {
		if !strings.Contains(got, want) {
			t.Errorf("search results: got = %q, want %q", got, want)
		}
	}
	if strings.Contains(got, "gamma three") {
		t.Errorf("search results: got = %q, want no %q", got, "gamma three")
	}
	if n := m.viewport.TotalLineCount(); n != 3 {
		t.Errorf("search result lines: got = %d, want = 3", n)
	}
	view := renderStripANSI(m.View())
	for _, want := range []string{"Search:", "alpha█", `Found 4 results (searching for: "alpha")`} {
		if !strings.Contains(view, want) {
			t.Errorf("search view: got = %q, want %q", view, want)
		}
	}

	m = teaKeys(t, m, tea.KeyMsg{Type: tea.KeyBackspace}, tea.KeyMsg{Type: tea.KeyEnter})
	if m.searchMode || m.searchTerm != "alph" {
		t.Errorf("after enter: got searchMode=%v term=%q, want searchMode=false term=%q", m.searchMode, m.searchTerm, "alph")
	}
	view = renderStripANSI(m.View())
	if strings.Contains(view, "Search:") || strings.Contains(view, "searching for") {
		t.Errorf("view after enter: got = %q, want no search prompt or status", view)
	}
	if n := m.viewport.TotalLineCount(); n != 3 {
		t.Errorf("results after enter: got = %d lines, want = 3", n)
	}

	m = teaKeys(t, m, teaRunes("/"))
	if view := renderStripANSI(m.View()); strings.Contains(view, "searching for") {
		t.Errorf("view with empty search term: got = %q, want no search status", view)
	}
	m = teaKeys(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.searchMode || m.searchTerm != "" || m.quitting {
		t.Errorf("after esc: got searchMode=%v term=%q quitting=%v, want all unset", m.searchMode, m.searchTerm, m.quitting)
	}
	if n := m.viewport.TotalLineCount(); n != len(results) {
		t.Errorf("results after esc: got = %d lines, want = %d", n, len(results))
	}
}

func TestMainModelSearchEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		results   []string
		keys      []tea.KeyMsg
		wantTerm  string
		wantLines int
		wantText  string
	}{
		{
			name:      "no match shows a message",
			results:   []string{"alpha one", "beta two"},
			keys:      []tea.KeyMsg{teaRunes("/"), teaRunes("z"), teaRunes("z"), teaRunes("z")},
			wantTerm:  "zzz",
			wantLines: 1,
			wantText:  "No matches found for: zzz",
		},
		{
			name:      "clearing the term restores all results",
			results:   []string{"alpha one", "beta two", "gamma three"},
			keys:      []tea.KeyMsg{teaRunes("/"), teaRunes("z"), {Type: tea.KeyBackspace}},
			wantLines: 3,
			wantText:  "gamma three",
		},
		{
			name:      "repeated matches keep the full line",
			results:   []string{"foo bar foo baz", "other"},
			keys:      []tea.KeyMsg{teaRunes("/"), teaRunes("f"), teaRunes("o"), teaRunes("o")},
			wantTerm:  "foo",
			wantLines: 2,
			wantText:  "foo bar foo baz",
		},
		{
			name:      "quit key is part of the search term",
			results:   []string{"quiet mode"},
			keys:      []tea.KeyMsg{teaRunes("/"), teaRunes("q")},
			wantTerm:  "q",
			wantLines: 1,
			wantText:  "quiet mode",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := teaKeys(t, teaReadyModel(t, tt.results...), tt.keys...)
			if m.searchTerm != tt.wantTerm || m.quitting {
				t.Errorf("model: got term=%q quitting=%v, want term=%q quitting=false", m.searchTerm, m.quitting, tt.wantTerm)
			}
			if n := m.viewport.TotalLineCount(); n != tt.wantLines {
				t.Errorf("viewport lines: got = %d, want = %d", n, tt.wantLines)
			}
			if got := teaVisible(m); !strings.Contains(got, tt.wantText) {
				t.Errorf("viewport: got = %q, want %q", got, tt.wantText)
			}
		})
	}
}

func TestMainModelHeaderWithoutRoomForGap(t *testing.T) {
	t.Parallel()
	m, _ := teaUpdate(t, newMainModel(), tea.WindowSizeMsg{Width: 20, Height: 30})
	header, _, _ := strings.Cut(renderStripANSI(m.View()), "\n")
	if want := "malcontent scan results↑/↓: scroll"; !strings.Contains(header, want) {
		t.Errorf("header in a narrow window: got = %q, want it to contain %q", header, want)
	}
}

func TestMainModelHeaderFillsWidth(t *testing.T) {
	t.Parallel()
	m := teaReadyModel(t)
	header, _, _ := strings.Cut(renderStripANSI(m.View()), "\n")
	if got := lipgloss.Width(header); got != m.width {
		t.Errorf("header width: got = %d, want = %d", got, m.width)
	}
	for _, want := range []string{"malcontent scan results", "q: quit"} {
		if !strings.Contains(header, want) {
			t.Errorf("header: got = %q, want %q", header, want)
		}
	}
}

// teaIdleInteractive returns an Interactive whose program never runs. Its
// context is already canceled, which turns Send into a no-op.
func teaIdleInteractive(t *testing.T) *Interactive {
	t.Helper()
	model := newMainModel()
	return &Interactive{
		writer:  io.Discard,
		model:   &model,
		program: tea.NewProgram(model, tea.WithContext(renderCanceledContext(t))),
	}
}

func TestNewInteractiveWriter(t *testing.T) {
	t.Parallel()
	if got := NewInteractive(nil).writer; got != io.Writer(os.Stdout) {
		t.Errorf("writer for nil: got = %v, want = os.Stdout", got)
	}
	var buf bytes.Buffer
	if got := NewInteractive(&buf).writer; got != io.Writer(&buf) {
		t.Errorf("writer: got = %v, want = the provided writer", got)
	}
	if got := NewInteractive(nil).Name(); got != "Interactive" {
		t.Errorf("Name: got = %q, want = %q", got, "Interactive")
	}
}

func TestInteractiveCanceledContext(t *testing.T) {
	t.Parallel()
	r := teaIdleInteractive(t)
	fr := &malcontent.FileReport{Path: "/bin/x", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{{ID: "net/connect", RiskScore: 3, RiskLevel: report.LevelHIGH}}}
	if err := r.File(renderCanceledContext(t), fr); !errors.Is(err, context.Canceled) {
		t.Errorf("File error: got = %v, want = %v", err, context.Canceled)
	}
	if err := r.Full(renderCanceledContext(t), &malcontent.Config{}, &malcontent.Report{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Full error: got = %v, want = %v", err, context.Canceled)
	}
}

func TestInteractiveAcceptsReports(t *testing.T) {
	t.Parallel()
	behaviors := func() []*malcontent.Behavior {
		return []*malcontent.Behavior{{ID: "net/connect", Description: "connects", RiskScore: 3, RiskLevel: report.LevelHIGH}}
	}
	files := []*malcontent.FileReport{
		nil,
		{Path: "/bin/skipped", Skipped: "data file"},
		{Path: "/bin/empty"},
		{Path: "/bin/tool", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: behaviors()},
	}
	for _, fr := range files {
		if err := teaIdleInteractive(t).File(t.Context(), fr); err != nil {
			t.Errorf("File(%+v): got err = %v, want = nil", fr, err)
		}
	}

	changed := behaviors()
	changed[0].DiffAdded = true
	reports := []struct {
		name string
		rep  *malcontent.Report
	}{
		{name: "nil report", rep: nil},
		{name: "report without diff", rep: &malcontent.Report{}},
		{name: "empty diff", rep: &malcontent.Report{Diff: renderDiff(nil, nil, nil)}},
		{name: "populated diff", rep: &malcontent.Report{Diff: renderDiff(
			[]*malcontent.FileReport{{Path: "/old/empty"}, {Path: "/old/tool", Behaviors: behaviors()}},
			[]*malcontent.FileReport{{Path: "/new/empty"}, {Path: "/new/tool", Behaviors: behaviors()}},
			[]*malcontent.FileReport{{Path: "/mod/same", Behaviors: behaviors()}, {Path: "/mod/changed", Behaviors: changed}},
		)}},
	}
	for _, tt := range reports {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := teaIdleInteractive(t).Full(t.Context(), &malcontent.Config{}, tt.rep); err != nil {
				t.Errorf("Full: got err = %v, want = nil", err)
			}
		})
	}
}
