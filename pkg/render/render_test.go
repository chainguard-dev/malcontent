// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/puzpuzpuz/xsync/v4"
)

func TestNew(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		kind    string
		wantErr bool
		wantNil bool
	}{
		{"empty string defaults to terminal", "", false, false},
		{"auto defaults to terminal", "auto", false, false},
		{"terminal", "terminal", false, false},
		{"terminal_brief", "terminal_brief", false, false},
		{"markdown", "markdown", false, false},
		{"yaml", "yaml", false, false},
		{"json", "json", false, false},
		{formatSimple, formatSimple, false, false},
		{formatStrings, formatStrings, false, false},
		{formatInteractive, formatInteractive, false, false},
		{"unknown renderer", "unknown", true, true},
		{"invalid renderer", "invalid-type", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.kind == formatInteractive {
				t.Skip() // this renderer causes test output artifacts
			}

			var buf bytes.Buffer
			got, err := New(tt.kind, &buf)

			if (err != nil) != tt.wantErr {
				t.Errorf("New() error: got = %v, want error = %v", err, tt.wantErr)
				return
			}

			if tt.wantNil && got != nil {
				t.Errorf("New() renderer for an invalid type: got = %T, want = nil", got)
			}

			if !tt.wantNil && got == nil {
				t.Error("New() renderer for a valid type: got = nil, want = non-nil")
			}

			// Verify renderer name matches (except for invalid types)
			if !tt.wantErr && got != nil {
				name := got.Name()
				if name == "" {
					t.Error("Name(): got = \"\", want = non-empty")
				}
			}
		})
	}
}

func TestRiskEmoji(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		score int
		want  string
	}{
		{"score 0 - low", 0, "🔵"},
		{"score 1 - low", 1, "🔵"},
		{"score 2 - medium", 2, "🟡"},
		{"score 3 - high", 3, "🛑"},
		{"score 4 - critical", 4, "😈"},
		{"negative score", -1, "🔵"},
		{"very high score", 10, "🔵"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := riskEmoji(tt.score)
			if got != tt.want {
				t.Errorf("riskEmoji(%d) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestSerializedStatsNilReport(t *testing.T) {
	t.Parallel()
	stats := serializedStats(nil, nil)
	if stats != nil {
		t.Errorf("serializedStats(nil): got = %+v, want = nil", stats)
	}
}

func TestNewJSON(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	if renderer.Name() != "JSON" {
		t.Errorf("NewJSON().Name() = %q, want %q", renderer.Name(), "JSON")
	}
}

func TestNewYAML(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	if renderer.Name() != "YAML" {
		t.Errorf("NewYAML().Name() = %q, want %q", renderer.Name(), "YAML")
	}
}

func TestNewMarkdown(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewMarkdown(&buf)

	if renderer.Name() != "Markdown" {
		t.Errorf("NewMarkdown().Name() = %q, want %q", renderer.Name(), "Markdown")
	}
}

func TestNewTerminal(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewTerminal(&buf)

	if renderer.Name() != "Terminal" {
		t.Errorf("NewTerminal().Name() = %q, want %q", renderer.Name(), "Terminal")
	}
}

func TestNewTerminalBrief(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewTerminalBrief(&buf)

	if renderer.Name() != "TerminalBrief" {
		t.Errorf("NewTerminalBrief().Name() = %q, want %q", renderer.Name(), "TerminalBrief")
	}
}

func TestNewSimple(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewSimple(&buf)

	if renderer.Name() != "Simple" {
		t.Errorf("NewSimple().Name() = %q, want %q", renderer.Name(), "Simple")
	}
}

func TestNewStringMatches(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewStringMatches(&buf)

	name := renderer.Name()
	if !strings.Contains(name, "String") {
		t.Errorf("NewStringMatches().Name(): got = %q, want it to contain %q", name, "String")
	}
}

func TestSanitizeUTF8(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"clean ASCII unchanged", "hello world", "hello world"},
		{"valid unicode unchanged", "café 日本語", "café 日本語"},
		{"invalid UTF-8 replaced", "hello\xffworld", "hello\ufffdworld"},
		{"multiple invalid bytes", "\xff\xfe\xfd", "\ufffd"},
		{"BiDi LRE stripped", "hello\u202Aworld", "helloworld"},
		{"BiDi RLE stripped", "hello\u202Bworld", "helloworld"},
		{"BiDi PDF stripped", "hello\u202Cworld", "helloworld"},
		{"BiDi LRO stripped", "hello\u202Dworld", "helloworld"},
		{"BiDi RLO stripped", "hello\u202Eworld", "helloworld"},
		{"BiDi LRI stripped", "hello\u2066world", "helloworld"},
		{"BiDi RLI stripped", "hello\u2067world", "helloworld"},
		{"BiDi FSI stripped", "hello\u2068world", "helloworld"},
		{"BiDi PDI stripped", "hello\u2069world", "helloworld"},
		{"LRM stripped", "hello\u200Eworld", "helloworld"},
		{"RLM stripped", "hello\u200Fworld", "helloworld"},
		{"multiple BiDi chars stripped", "\u202A\u202B\u200Ehello\u2066\u2067", "hello"},
		{"BiDi-only string becomes empty", "\u202A\u202B\u202C", ""},
		{"newline replaced with space", "line1\nline2", "line1 line2"},
		{"carriage return replaced with space", "line1\rline2", "line1 line2"},
		{"CRLF replaced with spaces", "line1\r\nline2", "line1  line2"},
		{"leading trailing whitespace trimmed", "  hello  ", "hello"},
		{"newlines at edges trimmed", "\nhello\n", "hello"},
		{"empty string", "", ""},
		{"combined invalid UTF-8 BiDi newlines", "\u202A\xff\nhello\u200E\r\xfe\u2069", "\ufffd hello \ufffd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeUTF8(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeUTF8(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("sanitizeUTF8(%q) produced invalid UTF-8: %q", tt.input, got)
			}
		})
	}
}

func TestSanitizeMarkdown(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain text unchanged", "hello world", "hello world"},
		{"open bracket escaped", "foo[bar", "foo\\[bar"},
		{"close bracket escaped", "foo]bar", "foo\\]bar"},
		{"open paren escaped", "foo(bar", "foo\\(bar"},
		{"close paren escaped", "foo)bar", "foo\\)bar"},
		{"backtick escaped", "foo`bar", "foo\\`bar"},
		{"markdown link fully escaped", "[click](http://evil.com)", "\\[click\\]\\(http:&#8203;//evil.com\\)"},
		{"nested brackets escaped", "[[nested]]", "\\[\\[nested\\]\\]"},
		{"all special chars together", "[]()` ", "\\[\\]\\(\\)\\` "},
		{"backslash escaped so it cannot escape the next character", `a\]`, `a\\\]`},
		{"pipe escaped so it cannot split a table cell", "a|b", `a\|b`},
		{"angle brackets escaped so they cannot open HTML", "<b>", `\<b\>`},
		{"emphasis and strikethrough markers escaped", "*a* _b_ ~c~", `\*a\* \_b\_ \~c\~`},
		{"math delimiter escaped", "$x$", `\$x\$`},
		{"line endings percent-encoded", "a\r\nb", "a%0D%0Ab"},
		{"last C0 control percent-encoded", "a\x1fb", "a%1Fb"},
		{"delete percent-encoded", "a\x7fb", "a%7Fb"},
		{"mention, reference, and emoji characters are followed by a zero-width space", "@a #1 :x:", "@&#8203;a #&#8203;1 :&#8203;x:&#8203;"},
		{"ampersand escaped before entities so spelled-out entities stay literal", "&#64; &amp;", "&amp;#&#8203;64; &amp;amp;"},
		{"other punctuation unchanged", "a.b-c/d!e%f=g;h", "a.b-c/d!e%f=g;h"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeMarkdown(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeMarkdown(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeFileReport(t *testing.T) {
	t.Parallel()

	t.Run("normal file report stored and sanitized", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Path:        "test\npath",
			ArchiveRoot: "/archive/root",
			FullPath:    "/full/path",
			Behaviors: []*malcontent.Behavior{
				{ID: "ns/technique\nwith-newline", Description: "desc\u202Awith-bidi"},
			},
		}
		files := make(map[string]*malcontent.FileReport)
		sanitizeFileReport("key\nwith-newline", fr, files)

		stored, ok := files["key with-newline"]
		if !ok {
			t.Fatalf("sanitized key %q: got = absent, want = present", "key with-newline")
		}
		if stored.ArchiveRoot != "" {
			t.Errorf("ArchiveRoot: got = %q, want = \"\"", stored.ArchiveRoot)
		}
		if stored.FullPath != "" {
			t.Errorf("FullPath: got = %q, want = \"\"", stored.FullPath)
		}
		if stored.Path != "test path" {
			t.Errorf("Path: got = %q, want = %q", stored.Path, "test path")
		}
		if stored.Behaviors[0].ID != "ns/technique with-newline" {
			t.Errorf("Behavior ID: got = %q, want = %q", stored.Behaviors[0].ID, "ns/technique with-newline")
		}
	})

	t.Run("skipped file not stored", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{Path: "path", Skipped: "data file"}
		files := make(map[string]*malcontent.FileReport)
		sanitizeFileReport("key", fr, files)
		if len(files) != 0 {
			t.Errorf("stored files for a skipped report: got = %d, want = 0", len(files))
		}
	})

	t.Run("nil behaviors tolerated", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Path:      "path",
			Behaviors: []*malcontent.Behavior{nil, {ID: "valid"}, nil},
		}
		files := make(map[string]*malcontent.FileReport)
		sanitizeFileReport("key", fr, files)
		if len(files) != 1 {
			t.Errorf("stored files: got = %d, want = 1", len(files))
		}
	})
}

func TestShortRisk(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{report.LevelCRITICAL, levelCRIT},
		{report.LevelMEDIUM, "MED"},
		{report.LevelHIGH, report.LevelHIGH},
		{report.LevelLOW, report.LevelLOW},
		{report.LevelNONE, report.LevelNONE},
		{"", ""},
		{"unknown", "unknown"},
		{"HALLO", "HALLO"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := ShortRisk(tt.input)
			if got != tt.want {
				t.Errorf("ShortRisk(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTruncateLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		limit int
		want  string
	}{
		{"shorter than limit", "hello", 10, "hello"},
		{"at limit", "hello", 5, "hello"},
		{"over limit", "hello world", 6, "hello…"},
		{"empty string", "", 10, ""},
		{"one over limit", "abcd", 3, "ab…"},
		{"long string", strings.Repeat("x", 200), 50, strings.Repeat("x", 49) + "…"},
		{"multibyte characters count by byte", "│ab", 3, "\xe2\x94…"},
	}

	// Text before the line's start is never shortened or counted.
	const before = "earlier output\n"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var b bytes.Buffer
			b.WriteString(before)
			b.WriteString(tt.input)
			truncateLine(&b, len(before), tt.limit)
			if got := b.String(); got != before+tt.want {
				t.Errorf("truncateLine(%q, %d): got = %q, want = %q", tt.input, tt.limit, got, before+tt.want)
			}
		})
	}
}

func TestAnsiLineLength(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"plain text", "hello", 5},
		{"empty string", "", 0},
		{"single ANSI color", "\x1b[31mhello\x1b[0m", 5},
		{"multiple ANSI codes", "\x1b[1m\x1b[31mhello\x1b[0m \x1b[32mworld\x1b[0m", 11},
		{"ANSI with semicolons", "\x1b[1;31;42mtext\x1b[0m", 4},
		{"cursor movement G", "\x1b[10Ghello", 5},
		{"only ANSI no text", "\x1b[31m\x1b[0m", 0},
		{"bracket without ESC is text", "a[31mb", 6},
		{"ESC without bracket is text", "\x1b]31mz", 6},
		{"ESC at the end is text", "ab\x1b", 3},
		{"byte other than a digit or semicolon ends the parameters", "\x1b[1!mX", 6},
		{"sequence cut off at the end is text", "\x1b[12", 4},
		{"sequence cut off after its bracket is text", "\x1b[", 2},
		{"reset without parameters", "\x1b[mab", 2},
		{"reset without parameters at the end", "ab\x1b[m", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ansiLineLength(tt.input)
			if got != tt.want {
				t.Errorf("ansiLineLength(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestSplitRuleID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    string
		wantNS   string
		wantRest string
	}{
		{"ns/resource/technique", "ns", "resource/technique"},
		{"a/b", "a", "b"},
		{formatSimple, formatSimple, ""},
		{"", "", ""},
		{"a/b/c/d", "a", "b/c/d"},
		{"/something", "", "something"},
		{"something/", "something", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			gotNS, gotRest := splitRuleID(tt.input)
			if gotNS != tt.wantNS || gotRest != tt.wantRest {
				t.Errorf("splitRuleID(%q) = (%q, %q), want (%q, %q)", tt.input, gotNS, gotRest, tt.wantNS, tt.wantRest)
			}
		})
	}
}

func TestNsLongName(t *testing.T) {
	t.Parallel()
	known := map[string]string{
		"c2": "command & control", "collect": "collection", "crypto": "cryptography",
		"discover": "discovery", "exfil": "exfiltration", "exec": "execution",
		"fs": "filesystem", "hw": "hardware", "net": "networking",
		"os": "operating-system", "3P": "third-party", "sus": "suspicious text",
		"persist": "persistence", "malware": "MALWARE FAMILY",
	}
	for abbr, want := range known {
		t.Run(abbr, func(t *testing.T) {
			t.Parallel()
			if got := nsLongName(abbr); got != want {
				t.Errorf("nsLongName(%q) = %q, want %q", abbr, got, want)
			}
		})
	}
	// Unknown returns as-is
	for _, u := range []string{"unknown", "foo", ""} {
		t.Run("unknown_"+u, func(t *testing.T) {
			t.Parallel()
			if got := nsLongName(u); got != u {
				t.Errorf("nsLongName(%q) = %q, want %q", u, got, u)
			}
		})
	}
}

func TestEvidenceString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ms   []string
		desc string
		want string
	}{
		{"normal strings joined", []string{"connect", "socket", "bind"}, "network", "connect, socket, bind"},
		{"short strings filtered", []string{"ab", "x", "connect"}, "", "connect"},
		{"two-char filtered", []string{"ab"}, "", ""},
		{"empty slice", []string{}, "", ""},
		{"nil slice", nil, "", ""},
		{"single valid item", []string{"malicious"}, "", "malicious"},
		{"strings matching desc excluded", []string{"connect", "socket"}, "uses connect to communicate", "socket"},
		{"exactly 3 chars included", []string{"abc"}, "", "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := evidenceString(tt.ms, tt.desc)
			if got != tt.want {
				t.Errorf("evidenceString(%v, %q) = %q, want %q", tt.ms, tt.desc, got, tt.want)
			}
		})
	}
}

func TestMatchFragmentLink(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, got string)
	}{
		{"dollar-prefixed becomes code span", "$xor_key", func(t *testing.T, got string) {
			t.Helper()
			if !strings.HasPrefix(got, "`") || !strings.HasSuffix(got, "`") {
				t.Errorf("code span: got = %q, want backtick fences", got)
			}
		}},
		{"https URL becomes markdown link", "https://evil.com/payload", func(t *testing.T, got string) {
			t.Helper()
			if !strings.Contains(got, "](") {
				t.Errorf("markdown link: got = %q, want a link", got)
			}
		}},
		{"http URL becomes markdown link", "http://example.com", func(t *testing.T, got string) {
			t.Helper()
			if !strings.Contains(got, "](") {
				t.Errorf("markdown link: got = %q, want a link", got)
			}
		}},
		{"plain string becomes GitHub search", "malicious_func", func(t *testing.T, got string) {
			t.Helper()
			if !strings.Contains(got, "github.com/search") {
				t.Errorf("GitHub search link: got = %q, want a github.com/search link", got)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := matchFragmentLink(tt.input)
			tt.check(t, got)
		})
	}
}

func TestPlural(t *testing.T) {
	t.Parallel()
	tests := []struct {
		word  string
		count int
		want  string
	}{
		{"rule", 0, "rule"},
		{"rule", 1, "rule"},
		{"rule", 2, "rules"},
		{"string", 100, formatStrings},
		{"item", -1, "item"},
	}

	for _, tt := range tests {
		t.Run(tt.word+"_"+strings.Replace(string(rune('0'+tt.count)), "-", "neg", 1), func(t *testing.T) {
			t.Parallel()
			got := plural(tt.word, tt.count)
			if got != tt.want {
				t.Errorf("plural(%q, %d) = %q, want %q", tt.word, tt.count, got, tt.want)
			}
		})
	}
}

func TestRiskStatistics(t *testing.T) {
	t.Parallel()

	t.Run("empty map", func(t *testing.T) {
		t.Parallel()
		files := xsync.NewMap[string, *malcontent.FileReport]()
		stats, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{}, files)
		if len(stats) != 0 || totalRisks != 0 || processed != 0 || skipped != 0 {
			t.Errorf("empty map: got stats=%d totalRisks=%d processed=%d skipped=%d, want all 0", len(stats), totalRisks, processed, skipped)
		}
	})

	t.Run("single file non-scan", func(t *testing.T) {
		t.Parallel()
		files := xsync.NewMap[string, *malcontent.FileReport]()
		files.Store("/bin/ls", &malcontent.FileReport{Path: "/bin/ls", RiskScore: 2, RiskLevel: report.LevelMEDIUM})
		stats, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{}, files)
		if processed != 1 || totalRisks != 1 || skipped != 0 {
			t.Errorf("single file: got processed=%d totalRisks=%d skipped=%d, want = 1 1 0", processed, totalRisks, skipped)
		}
		if len(stats) != 1 || stats[0].Key != 2 {
			t.Errorf("stats: got = %+v, want one entry with key 2", stats)
		}
	})

	t.Run("skipped files excluded non-scan", func(t *testing.T) {
		t.Parallel()
		files := xsync.NewMap[string, *malcontent.FileReport]()
		files.Store("/bin/ls", &malcontent.FileReport{Path: "/bin/ls", RiskScore: 2})
		files.Store("/bin/skip", &malcontent.FileReport{Path: "/bin/skip", Skipped: "data"})
		_, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{}, files)
		if processed != 2 || skipped != 1 || totalRisks != 1 {
			t.Errorf("totals: got processed=%d skipped=%d totalRisks=%d, want = 2 1 1", processed, skipped, totalRisks)
		}
	})

	t.Run("scan mode skips low risk", func(t *testing.T) {
		t.Parallel()
		files := xsync.NewMap[string, *malcontent.FileReport]()
		files.Store("/low", &malcontent.FileReport{Path: "/low", RiskScore: 1})
		files.Store("/high", &malcontent.FileReport{Path: "/high", RiskScore: 3})
		files.Store("/crit", &malcontent.FileReport{Path: "/crit", RiskScore: 4})
		_, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{Scan: true}, files)
		if processed != 3 || skipped != 1 || totalRisks != 2 {
			t.Errorf("totals: got processed=%d skipped=%d totalRisks=%d, want = 3 1 2", processed, skipped, totalRisks)
		}
	})
}

func TestPkgStatistics(t *testing.T) {
	t.Parallel()

	t.Run("empty map", func(t *testing.T) {
		t.Parallel()
		files := xsync.NewMap[string, *malcontent.FileReport]()
		stats, _, total := PkgStatistics(&malcontent.Config{}, files)
		if len(stats) != 0 || total != 0 {
			t.Errorf("empty map: got stats=%d total=%d, want both 0", len(stats), total)
		}
	})

	t.Run("behaviors counted", func(t *testing.T) {
		t.Parallel()
		files := xsync.NewMap[string, *malcontent.FileReport]()
		files.Store("/bin/ls", &malcontent.FileReport{
			Path:      "/bin/ls",
			Behaviors: []*malcontent.Behavior{{ID: "net/connect"}, {ID: "fs/read"}, {ID: "net/bind"}},
		})
		stats, _, total := PkgStatistics(&malcontent.Config{}, files)
		if total != 3 {
			t.Errorf("total behaviors: got = %d, want = 3", total)
		}
		if len(stats) != 3 {
			t.Errorf("stat entries: got = %d, want = 3", len(stats))
		}
	})

	t.Run("skipped files excluded", func(t *testing.T) {
		t.Parallel()
		files := xsync.NewMap[string, *malcontent.FileReport]()
		files.Store("/a", &malcontent.FileReport{Path: "/a", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}})
		files.Store("/skip", &malcontent.FileReport{Path: "/skip", Skipped: "reason", Behaviors: []*malcontent.Behavior{{ID: "bad"}}})
		_, _, total := PkgStatistics(&malcontent.Config{}, files)
		if total != 1 {
			t.Errorf("total behaviors: got = %d, want = 1", total)
		}
	})

	t.Run("duplicate IDs aggregated", func(t *testing.T) {
		t.Parallel()
		files := xsync.NewMap[string, *malcontent.FileReport]()
		files.Store("/a", &malcontent.FileReport{Path: "/a", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}})
		files.Store("/b", &malcontent.FileReport{Path: "/b", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}})
		stats, _, total := PkgStatistics(&malcontent.Config{}, files)
		if total != 2 {
			t.Errorf("total behaviors: got = %d, want = 2", total)
		}
		if len(stats) != 1 || stats[0].Count != 2 {
			t.Errorf("stats: got = %+v, want one entry with count 2", stats)
		}
	})
}
