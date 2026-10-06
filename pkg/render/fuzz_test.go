// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"gopkg.in/yaml.v3"
)

// FuzzRenderDifferential ensures JSON and YAML renderers produce semantically equivalent output.
func FuzzRenderDifferential(f *testing.F) {
	f.Add(int8(0), "/bin/ls", "test_behavior", "description", false)
	f.Add(int8(1), "/usr/bin/curl", "net/http", "HTTP client", false)
	f.Add(int8(2), "/tmp/test", "file/write", "Writes files", false)
	f.Add(int8(3), "/opt/app", "exec/shell", "Executes commands", false)
	f.Add(int8(4), "/sbin/daemon", "proc/fork", "Forks processes", false)
	f.Add(int8(2), "", "", "", false) // Empty strings
	f.Add(int8(1), "/path/with spaces", "behavior", "desc", false)
	f.Add(int8(3), "/path/with/unicode/世界", "test", "测试", false)
	f.Add(int8(2), "/path/with\"quotes'", "behave", "desc", false)
	f.Add(int8(1), "/path/with\nnewline", "test", "multiline\ndesc", false)
	f.Add(int8(0), "/very/long/"+strings.Repeat("path/", 50), "behavior", "description", false)
	f.Add(int8(4), "/bin/app", "critical", "Very dangerous", true) // With diff

	// YAML special values that cannot round-trip as map keys due to
	// YAML 1.1 merge key and implicit typing (boolean, null) semantics.
	yamlIgnore := map[string]struct{}{
		"<<": {}, "~": {},
		"null": {}, "Null": {}, "NULL": {},
		"true": {}, "True": {}, "TRUE": {},
		"false": {}, "False": {}, "FALSE": {},
		"yes": {}, "Yes": {}, "YES": {},
		"no": {}, "No": {}, "NO": {},
		"on": {}, "On": {}, "ON": {},
		"off": {}, "Off": {}, "OFF": {},
		"y": {}, "Y": {},
		"n": {}, "N": {},
	}

	f.Fuzz(func(t *testing.T, riskLevel int8, filePath, behaviorName, behaviorDesc string, hasDiff bool) {
		filePath = sanitizeUTF8(filePath)
		if _, ignored := yamlIgnore[filePath]; filePath == "" || ignored {
			return
		}

		risk := max(int(riskLevel)%5, 0)

		report := &malcontent.Report{
			Files: xsync.NewMap[string, *malcontent.FileReport](),
		}

		fileReport := &malcontent.FileReport{
			Path:      filePath,
			RiskScore: risk,
			RiskLevel: riskLevelString(risk),
		}

		if behaviorName != "" {
			fileReport.Behaviors = []*malcontent.Behavior{
				{
					ID:          behaviorName,
					Description: behaviorDesc,
					RiskScore:   risk,
				},
			}
		}

		report.Files.Store(filePath, fileReport)

		if hasDiff {
			report.Diff = &malcontent.DiffReport{
				Added:    orderedmap.New[string, *malcontent.FileReport](),
				Removed:  orderedmap.New[string, *malcontent.FileReport](),
				Modified: orderedmap.New[string, *malcontent.FileReport](),
			}
		}

		ctx := t.Context()
		cfg := &malcontent.Config{Stats: !hasDiff} // Stats only when no diff

		var jsonBuf bytes.Buffer
		jsonRenderer := NewJSON(&jsonBuf)
		if err := jsonRenderer.Full(ctx, cfg, report); err != nil {
			return
		}

		var yamlBuf bytes.Buffer
		yamlRenderer := NewYAML(&yamlBuf)
		if err := yamlRenderer.Full(ctx, cfg, report); err != nil {
			t.Fatalf("YAML rendering failed but JSON succeeded: %v", err)
		}

		var fromJSON, fromYAML Report

		if err := json.Unmarshal(jsonBuf.Bytes(), &fromJSON); err != nil {
			t.Fatalf("JSON unmarshal failed: %v\nJSON: %s", err, jsonBuf.String())
		}

		if err := yaml.Unmarshal(yamlBuf.Bytes(), &fromYAML); err != nil {
			t.Fatalf("YAML unmarshal failed: %v\nYAML: %s", err, yamlBuf.String())
		}

		if len(fromJSON.Files) != len(fromYAML.Files) {
			t.Errorf("File count mismatch: JSON=%d YAML=%d", len(fromJSON.Files), len(fromYAML.Files))
		}

		for key, jsonFR := range fromJSON.Files {
			yamlFR, ok := fromYAML.Files[key]
			if !ok {
				t.Errorf("File %q present in JSON but missing in YAML", key)
				continue
			}

			if jsonFR.Path != yamlFR.Path {
				t.Errorf("Path mismatch for %q: JSON=%q YAML=%q", key, jsonFR.Path, yamlFR.Path)
			}

			if jsonFR.RiskScore != yamlFR.RiskScore {
				t.Errorf("RiskScore mismatch for %q: JSON=%d YAML=%d", key, jsonFR.RiskScore, yamlFR.RiskScore)
			}

			if jsonFR.RiskLevel != yamlFR.RiskLevel {
				t.Errorf("RiskLevel mismatch for %q: JSON=%q YAML=%q", key, jsonFR.RiskLevel, yamlFR.RiskLevel)
			}

			if len(jsonFR.Behaviors) != len(yamlFR.Behaviors) {
				t.Errorf("Behavior count mismatch for %q: JSON=%d YAML=%d",
					key, len(jsonFR.Behaviors), len(yamlFR.Behaviors))
			}
		}

		compareDiffReports(t, fromJSON.Diff, fromYAML.Diff)

		if (fromJSON.Stats == nil) != (fromYAML.Stats == nil) {
			t.Errorf("Stats presence mismatch: JSON nil=%v, YAML nil=%v",
				fromJSON.Stats == nil, fromYAML.Stats == nil)
		}
	})
}

func riskLevelString(risk int) string {
	switch risk {
	case 0, 1:
		return "low"
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	default:
		return "unknown"
	}
}

// compareDiffReports compares two diff reports for equality.
func compareDiffReports(t *testing.T, jsonDiff, yamlDiff *malcontent.DiffReport) {
	t.Helper()

	if jsonDiff == nil && yamlDiff == nil {
		return
	}

	if (jsonDiff == nil) != (yamlDiff == nil) {
		t.Errorf("Diff presence mismatch: JSON nil=%v, YAML nil=%v",
			jsonDiff == nil, yamlDiff == nil)
		return
	}

	jsonAddedLen := orderedMapLen(jsonDiff.Added)
	yamlAddedLen := orderedMapLen(yamlDiff.Added)
	jsonRemovedLen := orderedMapLen(jsonDiff.Removed)
	yamlRemovedLen := orderedMapLen(yamlDiff.Removed)
	jsonModifiedLen := orderedMapLen(jsonDiff.Modified)
	yamlModifiedLen := orderedMapLen(yamlDiff.Modified)

	if jsonAddedLen != yamlAddedLen {
		t.Errorf("Diff Added count mismatch: JSON=%d YAML=%d", jsonAddedLen, yamlAddedLen)
	}
	if jsonRemovedLen != yamlRemovedLen {
		t.Errorf("Diff Removed count mismatch: JSON=%d YAML=%d", jsonRemovedLen, yamlRemovedLen)
	}
	if jsonModifiedLen != yamlModifiedLen {
		t.Errorf("Diff Modified count mismatch: JSON=%d YAML=%d", jsonModifiedLen, yamlModifiedLen)
	}
}

// orderedMapLen returns the length of an ordered map, or 0 if nil.
func orderedMapLen[K comparable, V any](m *orderedmap.OrderedMap[K, V]) int {
	if m == nil {
		return 0
	}
	return m.Len()
}

// FuzzSanitizeUTF8 tests that sanitizeUTF8 always produces valid, safe output.
func FuzzSanitizeUTF8(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add("\xff\xfe invalid utf8")
	f.Add("\u202Abidi\u202E")
	f.Add("\u200E\u200F LRM RLM")
	f.Add("\u2066\u2067\u2068\u2069")
	f.Add("line1\nline2\rline3")
	f.Add("  trimmed  ")
	f.Add("\u202A\xff\nhello\u200E\r\xfe\u2069")
	f.Add("café 日本語 🎉")
	f.Add(strings.Repeat("\u202A", 100))
	f.Add("\x00\x01\x02\x03")

	f.Fuzz(func(t *testing.T, input string) {
		result := sanitizeUTF8(input)

		// Must always be valid UTF-8
		if !utf8.ValidString(result) {
			t.Errorf("result is not valid UTF-8: %q", result)
		}

		// Must not contain any BiDi override characters
		for _, r := range result {
			if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F {
				t.Errorf("result contains BiDi char U+%04X: %q", r, result)
			}
		}

		// Must not contain newlines or carriage returns
		if strings.Contains(result, "\n") || strings.Contains(result, "\r") {
			t.Errorf("result contains newline/CR: %q", result)
		}

		// Must be trimmed
		if result != strings.TrimSpace(result) {
			t.Errorf("result not trimmed: %q", result)
		}
	})
}

// FuzzSanitizersAndLineLength tests properties of the sanitizers and the line
// measure for any input. sanitizeTerminal leaves no control or BiDi character
// and loses nothing else: unquoting its output as a Go string gives back the
// input with invalid UTF-8 replaced and BiDi controls dropped. sanitizeUTF8
// changes nothing on a second pass, nor in text that is valid, free of BiDi
// controls and line breaks, and trimmed already. ansiLineLength counts no more
// bytes than the input holds, agrees on strings and byte slices, and ignores a
// complete SGR sequence after the input.
func FuzzSanitizersAndLineLength(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add(" padded ")
	f.Add(`back\slash`)
	f.Add("\x1b[31mred\x1b[0m \x1b[10G \x1b[ \x1b")
	f.Add("\x1b[1;2;3m\x1b[;m\x1b[G\x1b[0x")
	f.Add("\xe2\x1b[0m\xf0\x9f\x1b[1m")
	f.Add("\u202Abidi\u202E\u0085\u00a0")
	f.Add("\t\v\f\x00\x7f\u009b")
	f.Add("café 日本語 🎉")

	f.Fuzz(func(t *testing.T, input string) {
		valid := strings.Map(func(r rune) rune {
			if isBiDiControl(r) {
				return -1
			}
			return r
		}, strings.ToValidUTF8(input, string(utf8.RuneError)))

		shown := sanitizeTerminal(input)
		if !utf8.ValidString(shown) {
			t.Errorf("sanitizeTerminal(%q): got = %q, want valid UTF-8", input, shown)
		}
		for _, r := range shown {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBiDiControl(r) {
				t.Errorf("sanitizeTerminal(%q): got %U in %q, want no control or BiDi character", input, r, shown)
			}
		}
		unquoted, err := strconv.Unquote(`"` + strings.ReplaceAll(shown, `"`, `\"`) + `"`)
		if err != nil {
			t.Fatalf("Unquote(sanitizeTerminal(%q)): got err = %v, want = nil", input, err)
		}
		if unquoted != valid {
			t.Errorf("sanitizeTerminal(%q) unquoted: got = %q, want = %q", input, unquoted, valid)
		}

		once := sanitizeUTF8(input)
		if twice := sanitizeUTF8(once); twice != once {
			t.Errorf("sanitizeUTF8(sanitizeUTF8(%q)): got = %q, want = %q", input, twice, once)
		}
		if valid == input && !strings.ContainsAny(input, "\n\r") && strings.TrimSpace(input) == input && once != input {
			t.Errorf("sanitizeUTF8(%q): got = %q, want = %q", input, once, input)
		}

		n := ansiLineLength(input)
		if n > len(input) {
			t.Errorf("ansiLineLength(%q): got = %d, want <= %d", input, n, len(input))
		}
		if got := ansiLineLength([]byte(input)); got != n {
			t.Errorf("ansiLineLength([]byte(%q)): got = %d, want = %d", input, got, n)
		}
		if got := ansiLineLength(input + "\x1b[0m"); got != n {
			t.Errorf("ansiLineLength(%q): got = %d, want = %d", input+"\x1b[0m", got, n)
		}
	})
}

// FuzzSanitizeMarkdown tests that sanitizeMarkdown escapes all dangerous characters.
func FuzzSanitizeMarkdown(f *testing.F) {
	f.Add("hello world")
	f.Add("[link](url)")
	f.Add("`code`")
	f.Add("[[nested]]")
	f.Add("")
	f.Add("no special chars")
	f.Add("[]()` all of them")
	f.Add(`a\]b\\|c<d>*e_f~g$h`)
	f.Add("line\r\nbreak\x00")
	f.Add("@user org/repo#12 :smile: &#64; &amp;")

	const zeroWidthSpace = "&#8203;"
	f.Fuzz(func(t *testing.T, input string) {
		result := sanitizeMarkdown(input)

		// A special byte is escaped only when an odd number of backslashes
		// precedes it; every other byte must follow an even number. Each '@',
		// '#', and ':' is followed by a zero-width space reference, and every
		// other '&' starts "&amp;".
		run := 0
		for i := 0; i < len(result); i++ {
			c := result[i]
			switch {
			case c == '\\':
				run++
				continue
			case c < 0x20 || c == 0x7f:
				t.Fatalf("control byte %#x at position %d in %q (from %q)", c, i, result, input)
			case c == '@' || c == '#' || c == ':':
				if !strings.HasPrefix(result[i+1:], zeroWidthSpace) {
					t.Fatalf("%q at position %d lacks a zero-width space in %q (from %q)", c, i, result, input)
				}
				if run%2 != 0 {
					t.Errorf("%q at position %d follows %d backslashes in %q (from %q)", c, i, run, result, input)
				}
				i += len(zeroWidthSpace)
			case c == '&':
				if !strings.HasPrefix(result[i:], "&amp;") {
					t.Fatalf("bare & at position %d in %q (from %q)", i, result, input)
				}
				if run%2 != 0 {
					t.Errorf("& at position %d follows %d backslashes in %q (from %q)", i, run, result, input)
				}
				i += len("&amp;") - 1
			case (strings.IndexByte(markdownTextSpecial, c) >= 0) != (run%2 == 1):
				t.Errorf("byte %q at position %d follows %d backslashes in %q (from %q)", c, i, run, result, input)
			}
			run = 0
		}
		if run%2 != 0 {
			t.Errorf("trailing unescaped backslash in %q (from %q)", result, input)
		}
	})
}

// FuzzTruncate tests that truncateLine never panics, respects length bounds,
// and leaves text before the line alone.
func FuzzTruncate(f *testing.F) {
	f.Add("hello", 10)
	f.Add("hello", 3)
	f.Add("", 0)
	f.Add(strings.Repeat("x", 1000), 50)
	f.Add("short", 5)
	f.Add("a", 1)

	const before = "│ earlier\n"
	f.Fuzz(func(t *testing.T, input string, limit int) {
		if limit < 1 || limit > 10000 {
			return
		}

		var b bytes.Buffer
		b.WriteString(before)
		b.WriteString(input)
		truncateLine(&b, len(before), limit)
		out := b.String()

		if !strings.HasPrefix(out, before) {
			t.Fatalf("truncateLine(%q, %d) = %q, changed the text before the line", input, limit, out)
		}
		result := out[len(before):]
		// Result length should never exceed input length + ellipsis overhead
		if len(result) > len(input)+3 {
			t.Errorf("truncateLine(%q, %d) = %q, too long", input, limit, result)
		}
		if len(input) <= limit && result != input {
			t.Errorf("truncateLine(%q, %d) = %q, want the line unchanged", input, limit, result)
		}
		if len(input) > limit && result != input[:limit-1]+"…" {
			t.Errorf("truncateLine(%q, %d) = %q, want %q", input, limit, result, input[:limit-1]+"…")
		}
	})
}

// FuzzNew tests the renderer factory with random renderer names.
func FuzzNew(f *testing.F) {
	// All known renderer names
	f.Add("terminal")
	f.Add("terminal_brief")
	f.Add("markdown")
	f.Add("yaml")
	f.Add("json")
	f.Add(formatSimple)
	f.Add(formatStrings)
	f.Add(formatInteractive)
	f.Add("auto")
	f.Add("")
	// Unknown / adversarial
	f.Add("TERMINAL")
	f.Add("unknown")
	f.Add("json; DROP TABLE")
	f.Add(strings.Repeat("x", 1000))
	f.Add("\x00\x01\x02")

	known := map[string]struct{}{
		"": {}, "auto": {}, "terminal": {}, "terminal_brief": {},
		"markdown": {}, "yaml": {}, "json": {},
		formatSimple: {}, formatStrings: {}, formatInteractive: {},
	}

	f.Fuzz(func(t *testing.T, kind string) {
		if kind == formatInteractive {
			t.Skip() // this renderer causes test output artifacts
		}

		var buf bytes.Buffer
		renderer, err := New(kind, &buf)

		if _, ok := known[kind]; ok {
			if err != nil {
				t.Errorf("New(%q) error: got = %v, want = nil", kind, err)
			}
			if renderer == nil {
				t.Errorf("New(%q) renderer: got = nil, want = non-nil for a known kind", kind)
			}
		} else if err == nil {
			t.Errorf("New(%q) error: got = nil, want = error for an unknown kind", kind)
		}
	})
}
