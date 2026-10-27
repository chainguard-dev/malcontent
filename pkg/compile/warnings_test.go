// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/chainguard-dev/malcontent/internal/yrx"
)

// gatedWarningCodes are the yara-x warnings that mark a rule as broken: a
// condition that can never hold, or a pattern set that takes in patterns its
// author did not mean. A bundled rule with one must be listed in
// rulesWithWarnings.
var gatedWarningCodes = map[string]struct{}{
	"unsatisfiable_expr":        {},
	"unintended_pattern_in_set": {},
}

// warningRuleSources hold, in one file, a rule without warnings, a rule whose
// condition can never hold, and a rule whose pattern set takes in a pattern
// named alike; a second file has no warnings.
var warningRuleSources = fstest.MapFS{
	"warn/mixed.yara": {Data: []byte(`rule warn_clean {
  strings:
    $a = "clean pattern"
  condition:
    $a
}

rule warn_unsatisfiable {
  strings:
    $a = "unsatisfiable"
  condition:
    $a and uint8(0) == 300
}

rule warn_pattern_set {
  strings:
    $foo    = "first pattern"
    $foobar = "second pattern"
  condition:
    any of ($foo*) and $foobar
}
`)},
	"warn/clean.yara": {Data: []byte(`rule other_clean {
  strings:
    $a = "another clean pattern"
  condition:
    $a
}
`)},
}

// warningSummary renders warnings as "code rule file:line", sorted.
func warningSummary(ws []ruleWarning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, fmt.Sprintf("%s %s %s:%d", w.code, w.rule, w.origin, w.line))
	}
	slices.Sort(out)
	return out
}

func TestCompileRecursiveAttributesWarnings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		fsys fs.FS
		want []string
	}{
		{
			name: "each warning names the rule and line it concerns",
			fsys: warningRuleSources,
			want: []string{
				"unintended_pattern_in_set warn_pattern_set warn/mixed.yara:20",
				"unsatisfiable_expr warn_unsatisfiable warn/mixed.yara:12",
			},
		},
		{
			name: "rules without warnings yield none",
			fsys: fstest.MapFS{"warn/clean.yara": warningRuleSources["warn/clean.yara"]},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yrs, ws, err := compileRecursive(t.Context(), []fs.FS{tt.fsys})
			if err != nil {
				t.Fatalf("compileRecursive: %v", err)
			}
			yrx.Destroy(yrs)
			if got := warningSummary(ws); !slices.Equal(got, tt.want) {
				t.Errorf("warnings: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestCompileFilesAttributesWarnings(t *testing.T) {
	t.Parallel()
	files, err := readSplitFiles(t.Context(), []fs.FS{warningRuleSources})
	if err != nil {
		t.Fatalf("readSplitFiles: %v", err)
	}
	tests := []struct {
		name string
		keep []string
		want []string
	}{
		{
			name: "a set holding every rule reports both warnings",
			keep: []string{"warn_clean", "warn_unsatisfiable", "warn_pattern_set", "other_clean"},
			want: []string{
				"unintended_pattern_in_set warn_pattern_set warn/mixed.yara:20",
				"unsatisfiable_expr warn_unsatisfiable warn/mixed.yara:12",
			},
		},
		{
			name: "a set without the first rule shifts lines but keeps rule names",
			keep: []string{"warn_pattern_set"},
			want: []string{"unintended_pattern_in_set warn_pattern_set warn/mixed.yara:6"},
		},
		{
			name: "a set of clean rules reports nothing",
			keep: []string{"warn_clean", "other_clean"},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yrs, ws, err := compileFilesWarnings(t.Context(), files, func(fi, ri int) bool {
				return slices.Contains(tt.keep, files[fi].rules[ri].name)
			})
			if err != nil {
				t.Fatalf("compileFilesWarnings: %v", err)
			}
			yrx.Destroy(yrs)
			if got := warningSummary(ws); !slices.Equal(got, tt.want) {
				t.Errorf("warnings: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestLogRuleWarnings checks that warnings are logged at debug level unless
// their rule is allowed to have them. Not parallel: it swaps the log
// functions.
func TestLogRuleWarnings(t *testing.T) {
	rec := compileRecordLogs(t)
	ws := []ruleWarning{
		{code: "unsatisfiable_expr", rule: "allowed_rule", origin: "a.yara", line: 3},
		{code: "unsatisfiable_expr", rule: "disabled_rule", origin: "a.yara", line: 9},
		{code: "non_bool_expr", rule: "other_rule", origin: "b.yara", line: 1},
	}
	tests := []struct {
		name  string
		allow map[string]bool
		want  int
	}{
		{"warnings of unlisted rules are logged", nil, 3},
		{"warnings of allowed rules are not logged", map[string]bool{"allowed_rule": true}, 2},
		{"rules listed for removal are still logged", map[string]bool{"allowed_rule": true, "disabled_rule": false}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec.reset()
			logRuleWarnings(ws, tt.allow)
			got := strings.Count(rec.String(), "DEBUG Rule compile warning")
			if got != tt.want {
				t.Errorf("debug warnings logged: got = %d, want = %d (%s)", got, tt.want, rec)
			}
			if strings.Contains(rec.String(), "WARN") {
				t.Errorf("warn-level messages: got %s, want none", rec)
			}
		})
	}
}

// TestBundledRuleWarningsAllowlisted fails on a bundled rule that gains a
// gated warning without being listed in rulesWithWarnings, and on a listed
// rule that no longer has any warning.
func TestBundledRuleWarningsAllowlisted(t *testing.T) {
	t.Parallel()
	yrs, ws, err := compileRecursive(t.Context(), getAllRuleFS())
	if err != nil {
		t.Fatalf("compileRecursive: %v", err)
	}
	yrx.Destroy(yrs)

	warned := map[string]struct{}{}
	for _, w := range ws {
		warned[w.rule] = struct{}{}
		if _, gated := gatedWarningCodes[w.code]; gated && !rulesWithWarnings[w.rule] {
			t.Errorf("%s: %s at %s:%d; fix the rule or list it in rulesWithWarnings", w.rule, w.code, w.origin, w.line)
		}
	}
	for _, rule := range slices.Sorted(maps.Keys(rulesWithWarnings)) {
		if _, ok := warned[rule]; rulesWithWarnings[rule] && !ok {
			t.Errorf("%s: listed in rulesWithWarnings but compiles without warnings; remove it", rule)
		}
	}
}
