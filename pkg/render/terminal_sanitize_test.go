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
		{name: "first C1 control", in: "a\u0080b", want: `a\u0080b`},
		{name: "last C1 control", in: "a\u009fb", want: `a\u009fb`},
		{name: "no-break space after the C1 controls unchanged", in: "a b", want: "a b"},
		{name: "space beside an escaped control unchanged", in: "a b\x01", want: `a b\x01`},
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

// TestSanitizersAndLineLength checks both sanitizers and the line measure on
// the same inputs: whitespace at the edges, each class of control character,
// backslashes, escape sequences, BiDi controls, invalid UTF-8, and multibyte
// text.
func TestSanitizersAndLineLength(t *testing.T) {
	t.Parallel()
	const punctuation = "~!@#$%^&*()_+{}|:<>?`-=[];',./\""
	long := strings.Repeat("a", 1000)
	tests := []struct {
		name         string
		in           string
		wantUTF8     string
		wantTerminal string
		wantLength   int
	}{
		{name: "empty", in: "", wantUTF8: "", wantTerminal: "", wantLength: 0},
		{name: "plain ASCII", in: "plain ascii", wantUTF8: "plain ascii", wantTerminal: "plain ascii", wantLength: 11},
		{name: "path", in: "/usr/bin/ls", wantUTF8: "/usr/bin/ls", wantTerminal: "/usr/bin/ls", wantLength: 11},
		{name: "leading space", in: " leading space", wantUTF8: "leading space", wantTerminal: " leading space", wantLength: 14},
		{name: "trailing space", in: "trailing space ", wantUTF8: "trailing space", wantTerminal: "trailing space ", wantLength: 15},
		{name: "tabs at the edges", in: "\ttab\t", wantUTF8: "tab", wantTerminal: `\ttab\t`, wantLength: 5},
		{name: "vertical tab and form feed at the edges", in: "\vvertical\f", wantUTF8: "vertical", wantTerminal: `\vvertical\f`, wantLength: 10},
		{name: "inner newline and carriage return", in: "inner\nnewline\rreturn", wantUTF8: "inner newline return", wantTerminal: `inner\nnewline\rreturn`, wantLength: 20},
		{name: "NUL", in: "nul\x00byte", wantUTF8: "nul\x00byte", wantTerminal: `nul\x00byte`, wantLength: 8},
		{name: "DEL", in: "del\x7fbyte", wantUTF8: "del\x7fbyte", wantTerminal: `del\x7fbyte`, wantLength: 8},
		{name: "inner backslash", in: `back\slash`, wantUTF8: `back\slash`, wantTerminal: `back\\slash`, wantLength: 10},
		{name: "lone backslash", in: `\`, wantUTF8: `\`, wantTerminal: `\\`, wantLength: 1},
		{name: "SGR sequences", in: "\x1b[31mred\x1b[0m", wantUTF8: "\x1b[31mred\x1b[0m", wantTerminal: `\x1b[31mred\x1b[0m`, wantLength: 3},
		{name: "next line and no-break space at the edges", in: "\u0085next line\u00a0", wantUTF8: "next line", wantTerminal: `\u0085next line` + "\u00a0", wantLength: 13},
		{name: "BiDi override, isolate, and mark", in: "bidi\u202Eoverride\u2066isolate\u200Emark", wantUTF8: "bidioverrideisolatemark", wantTerminal: "bidioverrideisolatemark", wantLength: 32},
		{name: "invalid UTF-8", in: "invalid\xff\xfeutf8", wantUTF8: "invalid\uFFFDutf8", wantTerminal: "invalid\uFFFDutf8", wantLength: 13},
		{name: "C1 control", in: "c1\u009bcontrol", wantUTF8: "c1\u009bcontrol", wantTerminal: `c1\u009bcontrol`, wantLength: 11},
		// U+061C ARABIC LETTER MARK, written as its UTF-8 bytes.
		{name: "Arabic letter mark is a BiDi control", in: "arabic\xd8\x9cmark", wantUTF8: "arabicmark", wantTerminal: "arabicmark", wantLength: 12},
		// U+200B ZERO WIDTH SPACE and U+FEFF ZERO WIDTH NO-BREAK SPACE.
		{name: "zero-width space and byte order mark", in: "zero\xe2\x80\x8bwidth\xef\xbb\xbf", wantUTF8: "zero\xe2\x80\x8bwidth\xef\xbb\xbf", wantTerminal: "zero\\u200bwidth\\ufeff", wantLength: 15},
		// U+00AD SOFT HYPHEN.
		{name: "soft hyphen", in: "soft\xc2\xadhyphen", wantUTF8: "soft\xc2\xadhyphen", wantTerminal: "soft\\u00adhyphen", wantLength: 12},
		{name: "multibyte text", in: "naïve 😈 文件", wantUTF8: "naïve 😈 文件", wantTerminal: "naïve 😈 文件", wantLength: 18},
		{name: "ASCII punctuation", in: punctuation, wantUTF8: punctuation, wantTerminal: punctuation, wantLength: 31},
		{name: "long", in: long, wantUTF8: long, wantTerminal: long, wantLength: 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sanitizeUTF8(tt.in); got != tt.wantUTF8 {
				t.Errorf("sanitizeUTF8(%q): got = %q, want = %q", tt.in, got, tt.wantUTF8)
			}
			if got := sanitizeTerminal(tt.in); got != tt.wantTerminal {
				t.Errorf("sanitizeTerminal(%q): got = %q, want = %q", tt.in, got, tt.wantTerminal)
			}
			if got := ansiLineLength(tt.in); got != tt.wantLength {
				t.Errorf("ansiLineLength(%q): got = %d, want = %d", tt.in, got, tt.wantLength)
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
				teaRender(t.Context(), terminalEvilReport(false), &buf)
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

const (
	terminalEvilNS          = "n\x1b[1As"
	terminalEvilNSShown     = `n\x1b[1As`
	terminalEvilRest        = "x\x1b]0;pwned\x07y"
	terminalEvilRestShown   = `x\x1b]0;pwned\ay`
	terminalEvilDesc        = "desc\x1b[2J\x1b[H"
	terminalEvilDescShown   = `desc\x1b[2J\x1b[H`
	terminalEvilAuthor      = "\x1b]8;;https://evil.example\x07click\x1b]8;;\x07"
	terminalEvilAuthorShown = `\x1b]8;;https://evil.example\aclick\x1b]8;;\a`
	terminalEvilLevel       = "HIGH\x1b[2J"
	terminalEvilLevelShown  = `HIGH\x1b[2J`
	terminalEvilRule        = "rule\x1b[2K"
	terminalEvilRuleShown   = `rule\x1b[2K`
)

// terminalEvilBehaviorReport returns a report with a plain path whose
// behavior fields and risk levels carry terminal control sequences, as a
// report file given to mal diff --report can.
func terminalEvilBehaviorReport(diffAdded bool) *malcontent.FileReport {
	return &malcontent.FileReport{
		Path:              "/bin/x",
		RiskScore:         3,
		RiskLevel:         terminalEvilLevel,
		PreviousRiskScore: 1,
		PreviousRiskLevel: terminalEvilLevel,
		Behaviors: []*malcontent.Behavior{{
			ID:           terminalEvilNS + "/" + terminalEvilRest,
			Description:  terminalEvilDesc,
			RuleAuthor:   terminalEvilAuthor,
			RuleName:     terminalEvilRule,
			MatchStrings: []string{"evidence"},
			RiskScore:    3,
			RiskLevel:    terminalEvilLevel,
			DiffAdded:    diffAdded,
		}},
	}
}

func TestTextRenderersEscapeBehaviorFields(t *testing.T) {
	t.Parallel()
	evilDiff := func() *malcontent.Report {
		return &malcontent.Report{Diff: renderDiff(
			[]*malcontent.FileReport{terminalEvilBehaviorReport(false)},
			nil,
			[]*malcontent.FileReport{terminalEvilBehaviorReport(true)},
		)}
	}
	behaviorLine := terminalEvilRestShown + " — " + terminalEvilDescShown + ", by " + terminalEvilAuthorShown
	evilID := terminalEvilNSShown + "/" + terminalEvilRestShown
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
				if err := NewTerminal(&buf).File(t.Context(), terminalEvilBehaviorReport(false)); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{"/bin/x [" + terminalEvilLevelShown + "]", terminalEvilNSShown + " [HIGH]", behaviorLine},
		},
		{
			name: "terminal diff",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewTerminal(&buf).Full(t.Context(), &malcontent.Config{}, evilDiff()); err != nil {
					t.Fatalf("Full: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{
				"Deleted: /bin/x [" + terminalEvilLevelShown + "]",
				behaviorLine,
				"Changed (1 added, 0 removed): /bin/x [" + terminalEvilLevelShown + " → " + terminalEvilLevelShown + "]",
				terminalEvilNSShown + " [HIGH]",
			},
		},
		{
			name: "terminal brief file",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewTerminalBrief(&buf).File(t.Context(), terminalEvilBehaviorReport(false)); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{evilID + " — " + terminalEvilDescShown},
		},
		{
			name: "simple file",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewSimple(&buf).File(t.Context(), terminalEvilBehaviorReport(false)); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{"# /bin/x: " + `high\x1b[2j` + "\n", evilID + ": " + `high\x1b[2j` + "\n"},
		},
		{
			name: "simple diff",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewSimple(&buf).Full(t.Context(), &malcontent.Config{}, evilDiff()); err != nil {
					t.Fatalf("Full: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{"-" + evilID + "\n", "+" + evilID + "\n"},
		},
		{
			name: "string matches file",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				if err := NewStringMatches(&buf).File(t.Context(), terminalEvilBehaviorReport(false)); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				return buf.String()
			},
			want: []string{"Matches for /bin/x [" + terminalEvilLevelShown + "]", terminalEvilRuleShown + " [HIGH]"},
		},
		{
			name: "interactive file summary",
			render: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				teaRender(t.Context(), terminalEvilBehaviorReport(false), &buf)
				return buf.String()
			},
			want: []string{terminalEvilLevelShown, terminalEvilNSShown, terminalEvilRestShown, terminalEvilDescShown, terminalEvilAuthorShown},
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
