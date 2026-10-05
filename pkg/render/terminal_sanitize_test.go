// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

// terminalSGRRe matches the SGR color sequences that malcontent's own styling emits.
var terminalSGRRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

const (
	terminalEvilPath       = "/tmp/a\x1b]0;pwned\x07b\rc\u009bd\x7fe.tar ∴ inner\x1b[2Jf"
	terminalEvilPathShown  = `/tmp/a\x1b]0;pwned\ab\rc\u009bd\x7fe.tar ∴ inner\x1b[2Jf`
	terminalEvilMatch      = "\x1b]8;;http://evil.example\x07click\x1b]8;;\x07\tend"
	terminalEvilMatchShown = `\x1b]8;;http://evil.example\aclick\x1b]8;;\a\tend`
)

func TestSanitizeTerminal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "CSI color and screen clear", in: "\x1b[31mred\x1b[0m\x1b[2J", want: `\x1b[31mred\x1b[0m\x1b[2J`},
		{name: "OSC window title", in: "\x1b]0;pwned\x07", want: `\x1b]0;pwned\a`},
		{name: "OSC 8 hyperlink", in: "\x1b]8;;https://evil.example\x1b\\click\x1b]8;;\x1b\\", want: `\x1b]8;;https://evil.example\x1b\\click\x1b]8;;\x1b\\`},
		{name: "carriage return that would overwrite the line", in: "safe.txt\rmalware.exe", want: `safe.txt\rmalware.exe`},
		{name: "bell", in: "ding\a", want: `ding\a`},
		{name: "C1 control sequence introducer", in: "a\u009b2Jb", want: `a\u009b2Jb`},
		{name: "delete", in: "a\x7fb", want: `a\x7fb`},
		{name: "backspace, tab, and newline", in: "a\bb\tc\nd", want: `a\bb\tc\nd`},
		{name: "NUL", in: "a\x00b", want: `a\x00b`},
		{name: "plain Unicode unchanged", in: "/usr/lib/文件/naïve 😈.so ∴ x", want: "/usr/lib/文件/naïve 😈.so ∴ x"},
		{name: "backslash doubled", in: `C:\temp`, want: `C:\\temp`},
		{name: "spelled-out escape reads differently from a real ESC", in: `\x1b[2J` + "\x1b[2J", want: `\\x1b[2J\x1b[2J`},
		{name: "BiDi override dropped", in: "evil\u202Etxt.exe", want: "eviltxt.exe"},
		{name: "invalid UTF-8 replaced", in: "a\xffb", want: "a\uFFFDb"},
		{name: "raw C1 byte is invalid UTF-8 and replaced", in: "a\x9bb", want: "a\uFFFDb"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sanitizeTerminal(tt.in); got != tt.want {
				t.Errorf("sanitizeTerminal(%q): got = %q, want = %q", tt.in, got, tt.want)
			}
		})
	}
}

// terminalRequireNoControls fails when out holds a control character other
// than a newline, after removing the SGR sequences malcontent's own styling emits.
func terminalRequireNoControls(t *testing.T, out string) {
	t.Helper()
	for i, r := range terminalSGRRe.ReplaceAllString(out, "") {
		if r == '\n' {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Errorf("control character %U at byte %d: got = present, want = escaped, in %q", r, i, out)
		}
	}
}

// terminalEvilReport returns a report whose path and evidence carry terminal control sequences.
func terminalEvilReport(diffAdded bool) *malcontent.FileReport {
	return &malcontent.FileReport{
		Path:              terminalEvilPath,
		RiskScore:         3,
		RiskLevel:         report.LevelHIGH,
		PreviousRiskScore: 3,
		PreviousRiskLevel: report.LevelHIGH,
		Behaviors: []*malcontent.Behavior{{
			ID:           "net/connect",
			Description:  "connects",
			MatchStrings: []string{terminalEvilMatch},
			RiskScore:    3,
			RiskLevel:    report.LevelHIGH,
			RuleName:     "net_connect",
			DiffAdded:    diffAdded,
		}},
	}
}

// terminalEvilDiff returns a diff with a deleted file and a moved file, both with malicious paths.
func terminalEvilDiff() *malcontent.Report {
	moved := terminalEvilReport(true)
	moved.PreviousPath = terminalEvilPath + "-old"
	return &malcontent.Report{Diff: renderDiff(
		[]*malcontent.FileReport{terminalEvilReport(false)},
		nil,
		[]*malcontent.FileReport{moved},
	)}
}

func TestTextRenderersEscapeTerminalControls(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		render func(t *testing.T) string
		want   []string
	}{
		{
			name: "terminal file",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewTerminal(&buf).File(t.Context(), terminalEvilReport(false)); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{terminalEvilPathShown + " [HIGH]", ": " + terminalEvilMatchShown},
		},
		{
			name: "terminal diff",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewTerminal(&buf).Full(t.Context(), &malcontent.Config{}, terminalEvilDiff()); err != nil {
					t.Fatalf("Full: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{
				"Deleted: " + terminalEvilPathShown + " [HIGH]",
				"Moved (1 added, 0 removed): " + terminalEvilPathShown + "-old -> " + terminalEvilPathShown,
				": " + terminalEvilMatchShown,
			},
		},
		{
			name: "terminal brief file",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewTerminalBrief(&buf).File(t.Context(), terminalEvilReport(false)); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{"├─ " + riskEmoji(3) + " " + terminalEvilPathShown + "\n", ": " + terminalEvilMatchShown},
		},
		{
			name: "simple file",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewSimple(&buf).File(t.Context(), terminalEvilReport(false)); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{"# " + terminalEvilPathShown + ": high\n"},
		},
		{
			name: "simple diff",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewSimple(&buf).Full(t.Context(), &malcontent.Config{}, terminalEvilDiff()); err != nil {
					t.Fatalf("Full: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{
				"--- missing: " + terminalEvilPathShown + "\n",
				">>> moved (1 added, 0 removed): " + terminalEvilPathShown + "-old -> " + terminalEvilPathShown + "\n",
			},
		},
		{
			name: "string matches file",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewStringMatches(&buf).File(t.Context(), terminalEvilReport(false)); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{"Matches for " + terminalEvilPathShown + " [HIGH]", "- " + terminalEvilMatchShown + "\n"},
		},
		{
			name: "interactive file summary",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				renderFileSummaryTea(t.Context(), terminalEvilReport(false), &buf, tableConfig{Title: terminalEvilPath})
				return buf.String()
			},
			want: []string{terminalEvilPathShown, terminalEvilMatchShown},
		},
		{
			name: "interactive scan status",
			render: func(t *testing.T) string {
				t.Helper()
				m, _ := teaUpdate(t, teaReadyModel(t), scanUpdateMsg{path: terminalEvilPath})
				return m.View()
			},
			want: []string{"Scanning: " + terminalEvilPathShown},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := tt.render(t)
			terminalRequireNoControls(t, out)
			shown := terminalSGRRe.ReplaceAllString(out, "")
			for _, w := range tt.want {
				if !strings.Contains(shown, w) {
					t.Errorf("output: got = %q, want it to contain %q", shown, w)
				}
			}
		})
	}
}
