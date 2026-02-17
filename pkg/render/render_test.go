// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
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
		{"simple", "simple", false, false},
		{"strings", "strings", false, false},
		{"interactive", "interactive", false, false},
		{"unknown renderer", "unknown", true, true},
		{"invalid renderer", "invalid-type", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.kind == "interactive" {
				t.Skip() // this renderer causes test output artifacts
			}

			var buf bytes.Buffer
			got, err := New(tt.kind, &buf)

			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantNil && got != nil {
				t.Errorf("New() expected nil renderer for invalid type, got %T", got)
			}

			if !tt.wantNil && got == nil {
				t.Error("New() returned nil renderer for valid type")
			}

			// Verify renderer name matches (except for invalid types)
			if !tt.wantErr && got != nil {
				name := got.Name()
				if name == "" {
					t.Error("renderer Name() returned empty string")
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
		t.Error("serializedStats with nil report should return nil")
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
		t.Errorf("NewStringMatches().Name() = %q, expected to contain 'String'", name)
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
		{"markdown link fully escaped", "[click](http://evil.com)", "\\[click\\]\\(http://evil.com\\)"},
		{"nested brackets escaped", "[[nested]]", "\\[\\[nested\\]\\]"},
		{"all special chars together", "[]()` ", "\\[\\]\\(\\)\\` "},
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

		if _, ok := files["key with-newline"]; !ok {
			t.Error("expected sanitized key 'key with-newline'")
		}
		stored := files["key with-newline"]
		if stored.ArchiveRoot != "" {
			t.Errorf("ArchiveRoot should be cleared, got %q", stored.ArchiveRoot)
		}
		if stored.FullPath != "" {
			t.Errorf("FullPath should be cleared, got %q", stored.FullPath)
		}
		if stored.Path != "test path" {
			t.Errorf("Path = %q, want %q", stored.Path, "test path")
		}
		if stored.Behaviors[0].ID != "ns/technique with-newline" {
			t.Errorf("Behavior ID = %q, want sanitized", stored.Behaviors[0].ID)
		}
	})

	t.Run("skipped file not stored", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{Path: "path", Skipped: "data file"}
		files := make(map[string]*malcontent.FileReport)
		sanitizeFileReport("key", fr, files)
		if len(files) != 0 {
			t.Errorf("expected empty map for skipped file, got %d", len(files))
		}
	})

	t.Run("non-string key ignored", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{Path: "path"}
		files := make(map[string]*malcontent.FileReport)
		sanitizeFileReport(42, fr, files)
		if len(files) != 0 {
			t.Errorf("expected empty map for non-string key, got %d", len(files))
		}
	})

	t.Run("non-FileReport value ignored", func(t *testing.T) {
		t.Parallel()
		files := make(map[string]*malcontent.FileReport)
		sanitizeFileReport("key", "not-a-report", files)
		if len(files) != 0 {
			t.Errorf("expected empty map for non-FileReport value, got %d", len(files))
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
			t.Errorf("expected 1 file, got %d", len(files))
		}
	})
}

func TestShortRisk(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"CRITICAL", "CRIT"},
		{"MEDIUM", "MED"},
		{"HIGH", "HIGH"},
		{"LOW", "LOW"},
		{"NONE", "NONE"},
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

func TestTruncate(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := truncate(tt.input, tt.limit)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.limit, got, tt.want)
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
		{"simple", "simple", ""},
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
				t.Errorf("expected backtick code span, got %q", got)
			}
		}},
		{"https URL becomes markdown link", "https://evil.com/payload", func(t *testing.T, got string) {
			t.Helper()
			if !strings.Contains(got, "](") {
				t.Errorf("expected markdown link, got %q", got)
			}
		}},
		{"http URL becomes markdown link", "http://example.com", func(t *testing.T, got string) {
			t.Helper()
			if !strings.Contains(got, "](") {
				t.Errorf("expected markdown link, got %q", got)
			}
		}},
		{"plain string becomes GitHub search", "malicious_func", func(t *testing.T, got string) {
			t.Helper()
			if !strings.Contains(got, "github.com/search") {
				t.Errorf("expected GitHub search link, got %q", got)
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
		{"string", 100, "strings"},
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
		files := &sync.Map{}
		stats, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{}, files)
		if len(stats) != 0 || totalRisks != 0 || processed != 0 || skipped != 0 {
			t.Errorf("empty map: stats=%d totalRisks=%d processed=%d skipped=%d", len(stats), totalRisks, processed, skipped)
		}
	})

	t.Run("single file non-scan", func(t *testing.T) {
		t.Parallel()
		files := &sync.Map{}
		files.Store("/bin/ls", &malcontent.FileReport{Path: "/bin/ls", RiskScore: 2, RiskLevel: "MEDIUM"})
		stats, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{}, files)
		if processed != 1 || totalRisks != 1 || skipped != 0 {
			t.Errorf("single file: processed=%d totalRisks=%d skipped=%d", processed, totalRisks, skipped)
		}
		if len(stats) != 1 || stats[0].Key != 2 {
			t.Errorf("expected 1 stat with key=2, got %v", stats)
		}
	})

	t.Run("skipped files excluded non-scan", func(t *testing.T) {
		t.Parallel()
		files := &sync.Map{}
		files.Store("/bin/ls", &malcontent.FileReport{Path: "/bin/ls", RiskScore: 2})
		files.Store("/bin/skip", &malcontent.FileReport{Path: "/bin/skip", Skipped: "data"})
		_, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{}, files)
		if processed != 2 || skipped != 1 || totalRisks != 1 {
			t.Errorf("processed=%d skipped=%d totalRisks=%d", processed, skipped, totalRisks)
		}
	})

	t.Run("scan mode skips low risk", func(t *testing.T) {
		t.Parallel()
		files := &sync.Map{}
		files.Store("/low", &malcontent.FileReport{Path: "/low", RiskScore: 1})
		files.Store("/high", &malcontent.FileReport{Path: "/high", RiskScore: 3})
		files.Store("/crit", &malcontent.FileReport{Path: "/crit", RiskScore: 4})
		_, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{Scan: true}, files)
		if processed != 3 || skipped != 1 || totalRisks != 2 {
			t.Errorf("processed=%d skipped=%d totalRisks=%d", processed, skipped, totalRisks)
		}
	})
}

func TestPkgStatistics(t *testing.T) {
	t.Parallel()

	t.Run("empty map", func(t *testing.T) {
		t.Parallel()
		files := &sync.Map{}
		stats, _, total := PkgStatistics(&malcontent.Config{}, files)
		if len(stats) != 0 || total != 0 {
			t.Errorf("empty: stats=%d total=%d", len(stats), total)
		}
	})

	t.Run("behaviors counted", func(t *testing.T) {
		t.Parallel()
		files := &sync.Map{}
		files.Store("/bin/ls", &malcontent.FileReport{
			Path:      "/bin/ls",
			Behaviors: []*malcontent.Behavior{{ID: "net/connect"}, {ID: "fs/read"}, {ID: "net/bind"}},
		})
		stats, _, total := PkgStatistics(&malcontent.Config{}, files)
		if total != 3 {
			t.Errorf("expected 3 behaviors, got %d", total)
		}
		if len(stats) != 3 {
			t.Errorf("expected 3 stat entries, got %d", len(stats))
		}
	})

	t.Run("skipped files excluded", func(t *testing.T) {
		t.Parallel()
		files := &sync.Map{}
		files.Store("/a", &malcontent.FileReport{Path: "/a", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}})
		files.Store("/skip", &malcontent.FileReport{Path: "/skip", Skipped: "reason", Behaviors: []*malcontent.Behavior{{ID: "bad"}}})
		_, _, total := PkgStatistics(&malcontent.Config{}, files)
		if total != 1 {
			t.Errorf("expected 1 behavior, got %d", total)
		}
	})

	t.Run("duplicate IDs aggregated", func(t *testing.T) {
		t.Parallel()
		files := &sync.Map{}
		files.Store("/a", &malcontent.FileReport{Path: "/a", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}})
		files.Store("/b", &malcontent.FileReport{Path: "/b", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}})
		stats, _, total := PkgStatistics(&malcontent.Config{}, files)
		if total != 2 {
			t.Errorf("expected 2 total, got %d", total)
		}
		if len(stats) != 1 || stats[0].Count != 2 {
			t.Errorf("expected 1 entry with count 2, got %v", stats)
		}
	})
}
