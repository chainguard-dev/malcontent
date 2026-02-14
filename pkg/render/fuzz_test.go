// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
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
	yamlIgnore := map[string]bool{
		"<<": true, "~": true,
		"null": true, "Null": true, "NULL": true,
		"true": true, "True": true, "TRUE": true,
		"false": true, "False": true, "FALSE": true,
		"yes": true, "Yes": true, "YES": true,
		"no": true, "No": true, "NO": true,
		"on": true, "On": true, "ON": true,
		"off": true, "Off": true, "OFF": true,
		"y": true, "Y": true,
		"n": true, "N": true,
	}

	f.Fuzz(func(t *testing.T, riskLevel int8, filePath, behaviorName, behaviorDesc string, hasDiff bool) {
		filePath = sanitizeUTF8(filePath)
		if filePath == "" || yamlIgnore[filePath] {
			return
		}

		risk := max(int(riskLevel)%5, 0)

		report := &malcontent.Report{
			Files: sync.Map{},
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

		ctx := context.Background()
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

// FuzzSanitizeMarkdown tests that sanitizeMarkdown escapes all dangerous characters.
func FuzzSanitizeMarkdown(f *testing.F) {
	f.Add("hello world")
	f.Add("[link](url)")
	f.Add("`code`")
	f.Add("[[nested]]")
	f.Add("")
	f.Add("no special chars")
	f.Add("[]()` all of them")

	f.Fuzz(func(t *testing.T, input string) {
		result := sanitizeMarkdown(input)

		// No unescaped brackets/parens/backticks should remain
		// Every [ ] ( ) ` in the result should be preceded by \
		for i, r := range result {
			if r == '[' || r == ']' || r == '(' || r == ')' || r == '`' {
				if i == 0 || result[i-1] != '\\' {
					t.Errorf("unescaped %c at position %d in %q (from %q)", r, i, result, input)
				}
			}
		}
	})
}

// FuzzTruncate tests that truncate never panics and respects length bounds.
func FuzzTruncate(f *testing.F) {
	f.Add("hello", 10)
	f.Add("hello", 3)
	f.Add("", 0)
	f.Add(strings.Repeat("x", 1000), 50)
	f.Add("short", 5)
	f.Add("a", 1)

	f.Fuzz(func(t *testing.T, input string, limit int) {
		if limit < 1 || limit > 10000 {
			return
		}

		result := truncate(input, limit)

		// Result length should never exceed input length + ellipsis overhead
		if len(result) > len(input)+3 {
			t.Errorf("truncate(%q, %d) = %q, too long", input, limit, result)
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
	f.Add("simple")
	f.Add("strings")
	f.Add("interactive")
	f.Add("auto")
	f.Add("")
	// Unknown / adversarial
	f.Add("TERMINAL")
	f.Add("unknown")
	f.Add("json; DROP TABLE")
	f.Add(strings.Repeat("x", 1000))
	f.Add("\x00\x01\x02")

	known := map[string]bool{
		"": true, "auto": true, "terminal": true, "terminal_brief": true,
		"markdown": true, "yaml": true, "json": true,
		"simple": true, "strings": true, "interactive": true,
	}

	f.Fuzz(func(t *testing.T, kind string) {
		if kind == "interactive" {
			t.Skip() // this renderer causes test output artifacts
		}

		var buf bytes.Buffer
		renderer, err := New(kind, &buf)

		if known[kind] {
			if err != nil {
				t.Errorf("New(%q) returned unexpected error: %v", kind, err)
			}
			if renderer == nil {
				t.Errorf("New(%q) returned nil renderer for known kind", kind)
			}
		} else if err == nil {
			t.Errorf("New(%q) should return error for unknown kind", kind)
		}
	})
}
