// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/fatih/color"
	"golang.org/x/term"
)

// The palette follows color.NoColor, so this test sets it and does not run
// in parallel.
func TestShortEvidenceMovesToItsOwnLineWithColor(t *testing.T) {
	if os.Getenv("NO_COLOR") != "" {
		t.Skip("NO_COLOR is set, so fatih/color writes no escape sequences")
	}
	saved := color.NoColor
	t.Cleanup(func() { color.NoColor = saved })
	color.NoColor = false

	// Four bytes of evidence after a description wider than the terminal stay
	// on the line without color, but not with it: the length once included
	// the color sequences.
	fr := func() *malcontent.FileReport {
		return &malcontent.FileReport{
			Path:      "/bin/x",
			RiskScore: 1,
			RiskLevel: report.LevelLOW,
			Behaviors: []*malcontent.Behavior{
				{ID: "net/connect", Description: strings.Repeat("d", 80), MatchStrings: []string{"abcd"}, RiskScore: 1, RiskLevel: report.LevelLOW},
			},
		}
	}
	tests := []struct {
		name string
		file func(io.Writer) error
		// line is the index of the behavior line.
		line     int
		evidence string
	}{
		{
			name:     "terminal",
			file:     func(w io.Writer) error { return (&Terminal{out: blockWriter{w: w}, width: 75}).File(t.Context(), fr()) },
			line:     2,
			evidence: "│          abcd",
		},
		{
			name: "terminal brief",
			file: func(w io.Writer) error {
				return (&TerminalBrief{out: blockWriter{w: w}, width: 75}).File(t.Context(), fr())
			},
			line:     1,
			evidence: briefIndent + "abcd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.file(&buf); err != nil {
				t.Fatalf("File: got err = %v, want = nil", err)
			}
			lines := strings.Split(renderStripANSI(buf.String()), "\n")
			if len(lines) < tt.line+2 {
				t.Fatalf("lines: got = %q, want at least %d", lines, tt.line+2)
			}
			if !strings.HasSuffix(lines[tt.line], ":") {
				t.Errorf("behavior line: got = %q, want suffix %q", lines[tt.line], ":")
			}
			if got := lines[tt.line+1]; got != tt.evidence {
				t.Errorf("evidence line: got = %q, want = %q", got, tt.evidence)
			}
		})
	}
}

var (
	// terminalNS prefixes unchanged namespace lines: the bar, a diff column, and a four-space indent.
	terminalNS = "│" + strings.Repeat(" ", 5)
	// terminalBehavior prefixes scan-mode behavior lines: the bar, a diff column, and a six-space indent.
	terminalBehavior = "│" + strings.Repeat(" ", 7)
)

// terminalSummary renders fr under title through renderFileSummary and returns the visible text.
func terminalSummary(t *testing.T, fr *malcontent.FileReport, title string) string {
	t.Helper()
	var buf bytes.Buffer
	renderFileSummary(t.Context(), &buf, fr, title, suggestedWidth())
	return renderStripANSI(buf.String())
}

func TestTerminalFileRendersNamespacesAndEvidence(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{
		Path:      "/bin/evil",
		RiskScore: 3,
		RiskLevel: report.LevelHIGH,
		Behaviors: []*malcontent.Behavior{
			{ID: "net/bind", Description: "binds a port", RiskScore: 1, RiskLevel: report.LevelLOW},
			{ID: "net/connect", Description: "connects to a host - via sockets", MatchStrings: []string{"AF_INET", "ab"}, RiskScore: 3, RiskLevel: report.LevelHIGH, RuleAuthor: "Alice"},
			{ID: "c2/beacon", Description: "beacons home", MatchStrings: []string{"beacon-url", "home"}, RiskScore: 4, RiskLevel: report.LevelCRITICAL},
		},
	}
	want := "├─ " + riskEmoji(3) + " /bin/evil [HIGH]\n" +
		terminalNS + "≡ networking [HIGH]\n" +
		terminalBehavior + riskEmoji(1) + " bind — binds a port\n" +
		terminalBehavior + riskEmoji(3) + " connect — connects to a host, by Alice: AF_INET\n" +
		terminalNS + "≡ command & control [CRITICAL]\n" +
		terminalBehavior + riskEmoji(4) + " beacon — beacons home: beacon-url\n" +
		"│\n"

	var buf bytes.Buffer
	if err := NewTerminal(&buf).File(t.Context(), fr); err != nil {
		t.Fatalf("File: got err = %v, want = nil", err)
	}
	if got := renderStripANSI(buf.String()); got != want {
		t.Errorf("File output:\ngot  = %q\nwant = %q", got, want)
	}
}

func TestTerminalFullRendersDiffSections(t *testing.T) {
	t.Parallel()
	rep := &malcontent.Report{Diff: renderDiff(
		[]*malcontent.FileReport{
			{Path: "/old/empty"},
			{Path: "/old/tool", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{
				{ID: "net/connect", Description: "connects", RiskScore: 3, RiskLevel: report.LevelHIGH},
			}},
		},
		[]*malcontent.FileReport{
			{Path: "/new/empty"},
			{Path: "/new/tool", RiskScore: 2, RiskLevel: report.LevelMEDIUM, Behaviors: []*malcontent.Behavior{
				{ID: "fs/write", Description: "writes files", RiskScore: 2, RiskLevel: report.LevelMEDIUM},
			}},
		},
		[]*malcontent.FileReport{
			{Path: "/mod/empty"},
			{Path: "/mod/same", RiskScore: 1, RiskLevel: report.LevelLOW, Behaviors: []*malcontent.Behavior{
				{ID: "net/bind", Description: "binds a port", RiskScore: 1, RiskLevel: report.LevelLOW},
			}},
			{Path: "/mod/changed", RiskScore: 3, RiskLevel: report.LevelHIGH, PreviousRiskScore: 1, PreviousRiskLevel: report.LevelLOW, Behaviors: []*malcontent.Behavior{
				{ID: "net/bind", Description: "binds a port", RiskScore: 1, RiskLevel: report.LevelLOW},
				{ID: "exec/shell", Description: "runs a shell", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
				{ID: "exec/system", Description: "calls system", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
			}},
			{Path: "/mod/steady", RiskScore: 2, RiskLevel: report.LevelMEDIUM, PreviousRiskScore: 2, PreviousRiskLevel: report.LevelMEDIUM, Behaviors: []*malcontent.Behavior{
				{ID: "fs/write", Description: "writes files", RiskScore: 2, RiskLevel: report.LevelMEDIUM},
				{ID: "fs/read", Description: "reads files", RiskScore: 1, RiskLevel: report.LevelLOW, DiffRemoved: true},
			}},
			{Path: "/mod/new-name", PreviousPath: "/mod/old-name", RiskScore: 2, RiskLevel: report.LevelMEDIUM, PreviousRiskScore: 2, PreviousRiskLevel: report.LevelMEDIUM, Behaviors: []*malcontent.Behavior{
				{ID: "crypto/aes", Description: "uses AES", RiskScore: 2, RiskLevel: report.LevelMEDIUM, DiffAdded: true},
				{ID: "crypto/rc4", Description: "uses RC4", RiskScore: 2, RiskLevel: report.LevelMEDIUM, DiffRemoved: true},
			}},
			{Path: "/mod/renamed", PreviousPath: "/mod/original", RiskScore: 3, RiskLevel: report.LevelHIGH, PreviousRiskScore: 2, PreviousRiskLevel: report.LevelMEDIUM, Behaviors: []*malcontent.Behavior{
				{ID: "exec/shell", Description: "runs a shell", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
			}},
		},
	)}

	var buf bytes.Buffer
	if err := NewTerminal(&buf).Full(t.Context(), &malcontent.Config{}, rep); err != nil {
		t.Fatalf("Full: got err = %v, want = nil", err)
	}
	got := renderStripANSI(buf.String())

	// Changed and moved files show the file-level risk transition in their title when the risk changed.
	headers := []string{
		"├─ " + riskEmoji(3) + " Deleted: /old/tool [HIGH]\n",
		"├─ " + riskEmoji(2) + " Added: /new/tool [MEDIUM]\n",
		"├─ " + riskEmoji(3) + " Changed (2 added, 0 removed): /mod/changed [LOW → HIGH]\n",
		"├─ " + riskEmoji(2) + " Changed (0 added, 1 removed): /mod/steady\n",
		"├─ " + riskEmoji(2) + " Moved (1 added, 1 removed): /mod/old-name -> /mod/new-name\n",
		"├─ " + riskEmoji(3) + " Moved (1 added, 0 removed): /mod/original -> /mod/renamed [MEDIUM → HIGH]\n",
	}
	if !renderIndexOrder(got, headers...) {
		t.Errorf("Full output: got = %q, want headers in order %q", got, headers)
	}
	for _, absent := range []string{"/old/empty", "/new/empty", "/mod/empty", "/mod/same"} {
		if strings.Contains(got, absent) {
			t.Errorf("Full output: got %q in %q, want = absent", absent, got)
		}
	}
	if n := strings.Count(got, "├─"); n != len(headers) {
		t.Errorf("Full file headers: got = %d, want = %d", n, len(headers))
	}
}

func TestRenderFileSummaryDiffMode(t *testing.T) {
	t.Parallel()
	changed := func() *malcontent.FileReport {
		return &malcontent.FileReport{
			Path:      "/bin/mod",
			RiskScore: 3,
			RiskLevel: report.LevelHIGH,
			Behaviors: []*malcontent.Behavior{
				{ID: "net/bind", Description: "binds a port", RiskScore: 1, RiskLevel: report.LevelLOW},
				{ID: "net/connect", Description: "connects", MatchStrings: []string{"AF_INET"}, RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
				{ID: "exec/shell", Description: "runs a shell", MatchStrings: []string{"/bin/sh"}, RiskScore: 2, RiskLevel: report.LevelMEDIUM, DiffRemoved: true},
				{ID: "crypto/aes", Description: "uses AES", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
			},
		}
	}
	// Unchanged behaviors are hidden, removed ones lose their evidence, and a
	// namespace whose risk rose shows the transition.
	changedBody := terminalNS + "≡ execution [MEDIUM]\n" +
		"│-      " + riskEmoji(2) + " shell — runs a shell\n" +
		terminalNS + "▲ networking [LOW → HIGH]\n" +
		"│+      " + riskEmoji(3) + " connect — connects: AF_INET\n" +
		"│+    ▲ cryptography [NONE → HIGH]\n" +
		"│+      " + riskEmoji(3) + " aes — uses AES\n" +
		"│\n"

	tests := []struct {
		name  string
		fr    *malcontent.FileReport
		title string
		want  string
	}{
		{
			name:  "changed file keeps the caller title with its risk transition",
			fr:    changed(),
			title: "Changed (2 added, 1 removed): /bin/mod [MEDIUM → HIGH]",
			want:  "├─ " + riskEmoji(3) + " Changed (2 added, 1 removed): /bin/mod [MEDIUM → HIGH]\n" + changedBody,
		},
		{
			name: "file with only added behaviors shows namespace risk without a transition",
			fr: &malcontent.FileReport{
				Path:      "/bin/new",
				RiskScore: 3,
				RiskLevel: report.LevelHIGH,
				Behaviors: []*malcontent.Behavior{
					{ID: "crypto/aes", Description: "uses AES", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
				},
			},
			title: "Changed (1 added, 0 removed): /bin/new",
			want: "├─ " + riskEmoji(3) + " Changed (1 added, 0 removed): /bin/new\n" +
				terminalNS + "≡ cryptography [HIGH]\n" +
				"│+      " + riskEmoji(3) + " aes — uses AES\n" +
				"│\n",
		},
		{
			name: "harmless unchanged behaviors do not mark other namespaces as changed",
			fr: &malcontent.FileReport{
				Path:      "/bin/new",
				RiskScore: 3,
				RiskLevel: report.LevelHIGH,
				Behaviors: []*malcontent.Behavior{
					{ID: "net/ping", Description: "pings hosts", RiskScore: 0, RiskLevel: report.LevelNONE},
					{ID: "crypto/aes", Description: "uses AES", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
				},
			},
			title: "Changed (1 added, 0 removed): /bin/new",
			want: "├─ " + riskEmoji(3) + " Changed (1 added, 0 removed): /bin/new\n" +
				terminalNS + "≡ networking [NONE]\n" +
				terminalNS + "≡ cryptography [HIGH]\n" +
				"│+      " + riskEmoji(3) + " aes — uses AES\n" +
				"│\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := terminalSummary(t, tt.fr, tt.title)
			if got != tt.want {
				t.Errorf("renderFileSummary output:\ngot  = %q\nwant = %q", got, tt.want)
			}
		})
	}
}

func TestRenderFileSummaryWritesNothing(t *testing.T) {
	t.Parallel()
	behaviors := []*malcontent.Behavior{{ID: "net/connect", Description: "connects", RiskScore: 3, RiskLevel: report.LevelHIGH}}

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		fr := &malcontent.FileReport{Path: "/bin/x", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: behaviors}
		renderFileSummary(renderCanceledContext(t), &buf, fr, "/bin/x", suggestedWidth())
		if buf.Len() != 0 {
			t.Errorf("renderFileSummary output: got = %q, want = empty", buf.String())
		}
	})
	t.Run("skipped report", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{Path: "/bin/x", Skipped: "too large", Behaviors: behaviors}
		if got := terminalSummary(t, fr, "/bin/x"); got != "" {
			t.Errorf("renderFileSummary output: got = %q, want = empty", got)
		}
	})
}

func TestRenderFileSummaryOrdersNamespacesByLongNameLength(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{Path: "/bin/x", RiskScore: 1, RiskLevel: report.LevelLOW}
	for _, id := range []string{"c2/a", "sus/b", "crypto/c", "net/d", "hw/e"} {
		fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{ID: id, Description: "does things", RiskScore: 1, RiskLevel: report.LevelLOW})
	}
	got := terminalSummary(t, fr, "/bin/x")
	want := []string{"≡ hardware [", "≡ networking [", "≡ cryptography [", "≡ suspicious text [", "≡ command & control ["}
	if !renderIndexOrder(got, want...) {
		t.Errorf("namespace order: got = %q, want order %q", got, want)
	}
}

func TestRenderFileSummaryKeepsFirstAppearanceForEqualLengthNames(t *testing.T) {
	t.Parallel()
	// networking, filesystem, and collection all have ten bytes.
	tests := []struct {
		name string
		ids  []string
		want []string
	}{
		{
			name: "networking first",
			ids:  []string{"net/a", "fs/b", "collect/c", "net/d"},
			want: []string{"≡ networking [", "a —", "d —", "≡ filesystem [", "b —", "≡ collection [", "c —"},
		},
		{
			name: "collection first",
			ids:  []string{"collect/c", "fs/b", "net/a"},
			want: []string{"≡ collection [", "c —", "≡ filesystem [", "b —", "≡ networking [", "a —"},
		},
		{
			name: "shorter name still leads",
			ids:  []string{"net/a", "hw/e", "fs/b"},
			want: []string{"≡ hardware [", "e —", "≡ networking [", "a —", "≡ filesystem [", "b —"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fr := &malcontent.FileReport{Path: "/bin/x", RiskScore: 1, RiskLevel: report.LevelLOW}
			for _, id := range tt.ids {
				fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{ID: id, Description: "does things", RiskScore: 1, RiskLevel: report.LevelLOW})
			}
			// Render repeatedly: the order must not vary between calls.
			for range 8 {
				if got := terminalSummary(t, fr, "/bin/x"); !renderIndexOrder(got, tt.want...) {
					t.Fatalf("namespace order: got = %q, want order %q", got, tt.want)
				}
			}
		})
	}
}

func TestRenderFileSummaryEvidenceLayout(t *testing.T) {
	t.Parallel()
	renderRequireNoColor(t)
	width := suggestedWidth()
	render := func(t *testing.T, desc, evidence string) []string {
		t.Helper()
		fr := &malcontent.FileReport{
			Path:      "/bin/x",
			RiskScore: 1,
			RiskLevel: report.LevelLOW,
			Behaviors: []*malcontent.Behavior{
				{ID: "net/connect", Description: desc, MatchStrings: []string{evidence}, RiskScore: 1, RiskLevel: report.LevelLOW},
				{ID: "net/listen", Description: "listens", RiskScore: 1, RiskLevel: report.LevelLOW},
			},
		}
		lines := strings.Split(terminalSummary(t, fr, "/bin/x"), "\n")
		if len(lines) < 5 {
			t.Fatalf("renderFileSummary lines: got = %q, want at least 5", lines)
		}
		return lines
	}
	listenLine := terminalBehavior + riskEmoji(1) + " listen — listens"

	const shortDesc = "opens a socket"
	const probe = "qqqqq"
	probeLines := render(t, shortDesc, probe)
	if !strings.HasSuffix(probeLines[2], ": "+probe) {
		t.Fatalf("probe behavior line: got = %q, want suffix %q", probeLines[2], ": "+probe)
	}
	// The width budget covers the behavior text plus evidence, excluding the bar and the ": " separator.
	contentLen := len(probeLines[2]) - len("│") - len(": ") - len(probe)
	longDesc := strings.Repeat("d", width)
	evidenceIndent := "│" + strings.Repeat(" ", 10)

	tests := []struct {
		name       string
		desc       string
		evidence   string
		wantSecond string
	}{
		{name: "evidence ending one byte before the width stays inline", desc: shortDesc, evidence: strings.Repeat("q", width-1-contentLen)},
		{name: "evidence reaching the width moves to its own line", desc: shortDesc, evidence: strings.Repeat("q", width-contentLen), wantSecond: evidenceIndent + strings.Repeat("q", width-contentLen)},
		{name: "evidence longer than the width is truncated with an ellipsis", desc: shortDesc, evidence: strings.Repeat("q", 2*width), wantSecond: evidenceIndent + strings.Repeat("q", width-1-len(evidenceIndent)) + "…"},
		{name: "four-byte evidence stays inline past the width", desc: longDesc, evidence: "abcd"},
		{name: "five-byte evidence past the width moves to its own line", desc: longDesc, evidence: "abcde", wantSecond: evidenceIndent + "abcde"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lines := render(t, tt.desc, tt.evidence)
			next := lines[3]
			if tt.wantSecond == "" {
				if !strings.HasSuffix(lines[2], ": "+tt.evidence) {
					t.Errorf("behavior line: got = %q, want suffix %q", lines[2], ": "+tt.evidence)
				}
			} else {
				if !strings.HasSuffix(lines[2], ":") {
					t.Errorf("behavior line: got = %q, want suffix %q", lines[2], ":")
				}
				if lines[3] != tt.wantSecond {
					t.Errorf("evidence line: got = %q, want = %q", lines[3], tt.wantSecond)
				}
				next = lines[4]
			}
			// The next behavior in the namespace still renders after the evidence.
			if next != listenLine {
				t.Errorf("line after evidence: got = %q, want = %q", next, listenLine)
			}
		})
	}
}

func TestSuggestedWidth(t *testing.T) {
	t.Parallel()
	got := suggestedWidth()
	if got < 75 {
		t.Errorf("suggestedWidth: got = %d, want >= 75", got)
	}
	if !term.IsTerminal(0) && got != 160 {
		t.Errorf("suggestedWidth without a terminal: got = %d, want = 160", got)
	}
}

// TestPaletteMatchesColorLibrary checks that the captured escape sequences
// write what fatih/color writes for the same attributes.
func TestPaletteMatchesColorLibrary(t *testing.T) {
	t.Parallel()
	attrs := []struct {
		name string
		got  sgr
		c    func() *color.Color
	}{
		{name: "plain", got: colorPalette.plain, c: func() *color.Color { return color.New() }},
		{name: "hi black", got: colorPalette.hiBlack, c: func() *color.Color { return color.New(color.FgHiBlack) }},
		{name: "hi red", got: colorPalette.hiRed, c: func() *color.Color { return color.New(color.FgHiRed) }},
		{name: "hi green", got: colorPalette.hiGreen, c: func() *color.Color { return color.New(color.FgHiGreen) }},
		{name: "hi yellow", got: colorPalette.hiYellow, c: func() *color.Color { return color.New(color.FgHiYellow) }},
		{name: "hi magenta", got: colorPalette.hiMagenta, c: func() *color.Color { return color.New(color.FgHiMagenta) }},
		{name: "hi cyan", got: colorPalette.hiCyan, c: func() *color.Color { return color.New(color.FgHiCyan) }},
		{name: "hi white", got: colorPalette.hiWhite, c: func() *color.Color { return color.New(color.FgHiWhite) }},
		{name: "white", got: colorPalette.white, c: func() *color.Color { return color.New(color.FgWhite) }},
		{name: "evidence", got: colorPalette.evidence, c: func() *color.Color { return color.RGB(255, 255, 255) }},
	}
	const text = "text"
	for _, a := range attrs {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			c := a.c()
			c.EnableColor()
			if got, want := a.got.sprint(text), c.Sprint(text); got != want {
				t.Errorf("sprint: got = %q, want = %q", got, want)
			}
			var b bytes.Buffer
			if _, err := c.Fprint(&b, text); err != nil {
				t.Fatalf("Fprint: got err = %v, want = nil", err)
			}
			if got, want := a.got.on+text+a.got.printOff, b.String(); got != want {
				t.Errorf("Fprint form: got = %q, want = %q", got, want)
			}
			if a.got.on == "" {
				t.Error("on: got = \"\", want = an escape sequence")
			}
		})
	}
	if plainPalette != (palette{}) {
		t.Errorf("plainPalette: got = %+v, want = no escape sequences", plainPalette)
	}
}
