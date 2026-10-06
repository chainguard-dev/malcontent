// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
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
		{
			name:      "escape clears the search term and restores all results",
			results:   []string{"alpha one", "beta two", "gamma three"},
			keys:      []tea.KeyMsg{teaRunes("/"), teaRunes("a"), teaRunes("l"), {Type: tea.KeyEsc}},
			wantLines: 3,
			wantText:  "gamma three",
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
	// The title keeps its two-column margin; the controls follow it directly.
	if want := "  malcontent scan results↑/↓: scroll • /: search • q: quit"; header != want {
		t.Errorf("header in a narrow window: got = %q, want = %q", header, want)
	}
}

func TestMainModelViewLayout(t *testing.T) {
	t.Parallel()
	ready := teaReadyModel(t, "first finding")
	scanning, _ := teaUpdate(t, ready, scanUpdateMsg{path: "/bin/scanning-now"})
	searching := teaKeys(t, ready, teaRunes("/"), teaRunes("f"), teaRunes("i"))
	tests := []struct {
		name string
		m    mainModel
		// status is the line between the header and the viewport, if any.
		status string
	}{
		{name: "results only", m: ready},
		{name: "scan status on its own line", m: scanning, status: "Scanning: /bin/scanning-now"},
		{name: "search prompt on its own line", m: searching, status: " Search:  fi█"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lines := strings.Split(renderStripANSI(tt.m.View()), "\n")
			top := 1
			if tt.status != "" {
				top = 2
				// The spinner leads the scan status, so only its end is fixed.
				if got := lines[1]; got != tt.status && !strings.HasSuffix(got, " "+tt.status) {
					t.Errorf("status line: got = %q, want = %q", got, tt.status)
				}
			}
			if len(lines) < top+3 {
				t.Fatalf("view lines: got = %q, want the viewport after line %d", lines, top)
			}
			// The viewport has a border, one blank line of padding, and two
			// columns of padding before its content.
			if !strings.HasPrefix(lines[top], "╭─") {
				t.Errorf("viewport top: got = %q, want a border", lines[top])
			}
			if got := teaTrimBox(lines[top+1]); got != "" {
				t.Errorf("viewport padding line: got = %q, want = blank", got)
			}
			if got, want := teaTrimBox(lines[top+2]), "│  first finding"; got != want {
				t.Errorf("viewport content line: got = %q, want = %q", got, want)
			}
		})
	}
}

func TestMainModelEnterReappliesSearch(t *testing.T) {
	t.Parallel()
	m := teaReadyModel(t, "alpha one", "beta two", "gamma three")
	m = teaKeys(t, m, teaRunes("/"), teaRunes("a"), teaRunes("l"))
	// A result that arrives during a search shows every result again.
	m, _ = teaUpdate(t, m, resultUpdateMsg{content: "delta four", isResult: true})
	if n := m.viewport.TotalLineCount(); n != 4 {
		t.Fatalf("viewport lines after a new result: got = %d, want = 4", n)
	}
	// Enter filters them again: the match and the line after it.
	m = teaKeys(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if n := m.viewport.TotalLineCount(); n != 2 {
		t.Errorf("viewport lines after enter: got = %d, want = 2", n)
	}
	if got := teaVisible(m); !strings.Contains(got, "alpha one") || strings.Contains(got, "delta four") {
		t.Errorf("viewport after enter: got = %q, want alpha one without delta four", got)
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

// teaMark is a message a test sends after others to learn when the program
// has handled everything sent before it.
type teaMark struct{}

// teaRecorder is a program model that forwards the messages an Interactive
// sends to msgs. It ends the program when the scan completes, once release
// closes if release is not nil.
type teaRecorder struct {
	msgs    chan<- tea.Msg
	release <-chan struct{}
}

func (m teaRecorder) Init() tea.Cmd { return nil }

func (m teaRecorder) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg.(type) {
	case scanUpdateMsg, resultUpdateMsg, teaMark:
		m.msgs <- msg
	case scanCompleteMsg:
		m.msgs <- msg
		if m.release != nil {
			<-m.release
		}
		return m, tea.Quit
	}
	return m, nil
}

func (m teaRecorder) View() string { return "" }

// teaLockedWriter collects what a program writes from several goroutines.
type teaLockedWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *teaLockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *teaLockedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// teaRecording starts an Interactive whose program runs rec without a
// terminal: it reads no input and writes to out. When the test ends, the
// program is stopped unless Full already ended it.
func teaRecording(t *testing.T, rec teaRecorder, out io.Writer) *Interactive {
	t.Helper()
	r := &Interactive{
		writer:  io.Discard,
		program: tea.NewProgram(rec, tea.WithInput(nil), tea.WithOutput(out), tea.WithoutSignalHandler()),
	}
	r.Start()
	t.Cleanup(func() {
		r.program.Quit()
		r.wg.Wait()
	})
	return r
}

// teaReceived sends a mark through r's program and returns the messages the
// program handled before it, in order.
func teaReceived(r *Interactive, msgs <-chan tea.Msg) []tea.Msg {
	r.program.Send(teaMark{})
	var got []tea.Msg
	for msg := range msgs {
		if _, ok := msg.(teaMark); ok {
			break
		}
		got = append(got, msg)
	}
	return got
}

// teaDrained returns the messages left in msgs after the program has ended.
func teaDrained(msgs <-chan tea.Msg) []tea.Msg {
	var got []tea.Msg
	for {
		select {
		case msg := <-msgs:
			got = append(got, msg)
		default:
			return got
		}
	}
}

// teaResult returns the message an Interactive sends for fr's summary.
func teaResult(t *testing.T, fr *malcontent.FileReport) resultUpdateMsg {
	t.Helper()
	var b strings.Builder
	renderFileSummaryTea(t.Context(), fr, &b)
	return resultUpdateMsg{content: strings.TrimSpace(b.String()), isResult: true}
}

// teaCaptureStderr returns what run writes to os.Stderr. It swaps os.Stderr,
// so callers must not run in parallel.
func teaCaptureStderr(t *testing.T, run func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: got err = %v, want = nil", err)
	}
	stderr := os.Stderr
	t.Cleanup(func() { os.Stderr = stderr })
	os.Stderr = w
	run()
	os.Stderr = stderr
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: got err = %v, want = nil", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: got err = %v, want = nil", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close pipe reader: got err = %v, want = nil", err)
	}
	return string(out)
}

// Start writes to os.Stderr, so this test swaps it and must not run in parallel.
func TestInteractiveStartReportsRunErrors(t *testing.T) {
	tests := []struct {
		name       string
		canceled   bool
		wantPrefix string
	}{
		{name: "program that quits prints nothing"},
		{name: "program that fails prints its error", canceled: true, wantPrefix: "Error running program: program was killed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []tea.ProgramOption{tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutSignalHandler()}
			if tt.canceled {
				// A program whose context is already canceled stops at once with an error.
				opts = append(opts, tea.WithContext(renderCanceledContext(t)))
			}
			r := &Interactive{writer: io.Discard, program: tea.NewProgram(teaRecorder{msgs: make(chan tea.Msg, 1)}, opts...)}
			got := teaCaptureStderr(t, func() {
				r.Start()
				if !tt.canceled {
					r.program.Quit()
				}
				r.wg.Wait()
			})
			if tt.wantPrefix == "" {
				if got != "" {
					t.Errorf("stderr: got = %q, want = empty", got)
				}
				return
			}
			if !strings.HasPrefix(got, tt.wantPrefix) || !strings.HasSuffix(got, "\n") {
				t.Errorf("stderr: got = %q, want one line starting with %q", got, tt.wantPrefix)
			}
		})
	}
}

func TestInteractiveScanningSendsThePath(t *testing.T) {
	t.Parallel()
	msgs := make(chan tea.Msg, 16)
	r := teaRecording(t, teaRecorder{msgs: msgs}, io.Discard)
	r.Scanning(renderCanceledContext(t), "/bin/canceled")
	r.Scanning(t.Context(), "/bin/live")
	want := []tea.Msg{scanUpdateMsg{path: "/bin/live"}}
	if got := teaReceived(r, msgs); !slices.Equal(got, want) {
		t.Errorf("messages: got = %v, want = %v", got, want)
	}
}

func TestInteractiveFileSendsResults(t *testing.T) {
	t.Parallel()
	tool := &malcontent.FileReport{Path: "/bin/tool", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{
		{ID: "net/connect", Description: "connects", RiskScore: 3, RiskLevel: report.LevelHIGH},
	}}
	tests := []struct {
		name string
		fr   *malcontent.FileReport
		want []tea.Msg
	}{
		{name: "missing report sends nothing"},
		{name: "report without behaviors sends nothing", fr: &malcontent.FileReport{Path: "/bin/empty"}},
		{name: "skipped report is sent as a skip, not a result", fr: &malcontent.FileReport{Path: "/bin/skip\x1b", Skipped: "data\tfile"}, want: []tea.Msg{resultUpdateMsg{content: `skipped /bin/skip\x1b: data\tfile`}}},
		{name: "report with one behavior is sent as a result", fr: tool, want: []tea.Msg{teaResult(t, tool)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msgs := make(chan tea.Msg, 16)
			r := teaRecording(t, teaRecorder{msgs: msgs}, io.Discard)
			if err := r.File(t.Context(), tt.fr); err != nil {
				t.Fatalf("File: got err = %v, want = nil", err)
			}
			if got := teaReceived(r, msgs); !slices.Equal(got, tt.want) {
				t.Errorf("messages: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestInteractiveFullSendsChangedFiles(t *testing.T) {
	t.Parallel()
	file := func(path string, n int, added, removed bool) *malcontent.FileReport {
		fr := &malcontent.FileReport{Path: path, RiskScore: 2, RiskLevel: report.LevelMEDIUM}
		for i := range n {
			fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{
				ID:          fmt.Sprintf("net/b%d", i),
				Description: "does things",
				RiskScore:   2,
				RiskLevel:   report.LevelMEDIUM,
				DiffAdded:   added,
				DiffRemoved: removed,
			})
		}
		return fr
	}
	removedOne, removedTwo := file("/old/one", 1, false, false), file("/old/two", 2, false, false)
	addedOne := file("/new/one", 1, false, false)
	modRemoved, modAdded := file("/mod/removed", 1, false, true), file("/mod/added", 1, true, false)
	// Files that must be skipped come first in each section, so skipping one
	// must not end its section.
	diff := renderDiff(
		[]*malcontent.FileReport{file("/old/empty", 0, false, false), removedOne, removedTwo},
		[]*malcontent.FileReport{file("/new/empty", 0, false, false), addedOne},
		[]*malcontent.FileReport{file("/mod/same", 2, false, false), modRemoved, modAdded},
	)
	tests := []struct {
		name string
		rep  *malcontent.Report
		want []tea.Msg
	}{
		{name: "missing report only completes the scan", want: []tea.Msg{scanCompleteMsg{}}},
		{name: "report without a diff only completes the scan", rep: &malcontent.Report{}, want: []tea.Msg{scanCompleteMsg{}}},
		{name: "diff sends each file whose behaviors changed", rep: &malcontent.Report{Diff: diff}, want: []tea.Msg{
			teaResult(t, removedOne), teaResult(t, removedTwo), teaResult(t, addedOne), teaResult(t, modRemoved), teaResult(t, modAdded), scanCompleteMsg{},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msgs := make(chan tea.Msg, 16)
			r := teaRecording(t, teaRecorder{msgs: msgs}, io.Discard)
			if err := r.Full(t.Context(), &malcontent.Config{}, tt.rep); err != nil {
				t.Fatalf("Full: got err = %v, want = nil", err)
			}
			// Full returns after the program has ended, so every message is in.
			if got := teaDrained(msgs); !slices.Equal(got, tt.want) {
				t.Errorf("messages: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestInteractiveFullWaitsForTheProgram(t *testing.T) {
	t.Parallel()
	msgs := make(chan tea.Msg, 16)
	release := make(chan struct{})
	out := &teaLockedWriter{}
	r := teaRecording(t, teaRecorder{msgs: msgs, release: release}, out)
	// Cleanups run last first, so this lets the program end before the
	// recording's cleanup waits for it.
	releaseProgram := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseProgram)

	done := make(chan error, 1)
	go func() { done <- r.Full(t.Context(), &malcontent.Config{}, nil) }()
	// The program holds on to the completion message until it is released.
	for msg := range msgs {
		if _, ok := msg.(scanCompleteMsg); ok {
			break
		}
	}
	releaseProgram()
	if err := <-done; err != nil {
		t.Fatalf("Full: got err = %v, want = nil", err)
	}
	// Showing the cursor again is part of restoring the terminal, the last
	// thing the program does before it returns.
	if got := out.String(); !strings.Contains(got, "\x1b[?25h") {
		t.Errorf("program output when Full returned: got = %q, want the cursor shown again", got)
	}
}
