// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateIgnoreRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		patterns []string
		wantErr  bool
	}{
		{name: "nil", patterns: nil, wantErr: false},
		{name: "empty", patterns: []string{}, wantErr: false},
		{name: "single exact", patterns: []string{"py_lib_alias_val"}, wantErr: false},
		{name: "glob star", patterns: []string{"py_lib_*"}, wantErr: false},
		{name: "glob question", patterns: []string{"py_lib_?"}, wantErr: false},
		{name: "glob class", patterns: []string{"py_lib_[a-z]*"}, wantErr: false},
		{name: "multiple", patterns: []string{"a", "b", "py_*"}, wantErr: false},
		{name: "whitespace only", patterns: []string{"  "}, wantErr: false},
		{name: "unclosed class", patterns: []string{"py_lib_[abc"}, wantErr: true},
		{name: "escape at end", patterns: []string{`py_\`}, wantErr: true},
		{name: "malformed among valid", patterns: []string{"good", "py_lib_[abc"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateIgnoreRules(tt.patterns)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateIgnoreRules(%v) err = %v, wantErr = %v", tt.patterns, err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !errors.Is(err, filepath.ErrBadPattern) {
				t.Errorf("expected error to wrap filepath.ErrBadPattern, got %v", err)
			}
		})
	}
}

func TestRuleExcluded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		rule     string
		patterns []string
		want     bool
	}{
		{name: "empty list", rule: "any_rule", patterns: nil, want: false},
		{name: "empty slice", rule: "any_rule", patterns: []string{}, want: false},
		{name: "exact match", rule: "py_lib_alias_val", patterns: []string{"py_lib_alias_val"}, want: true},
		{name: "exact no match", rule: "py_lib_alias_val", patterns: []string{"other_rule"}, want: false},
		{name: "glob star match", rule: "py_lib_alias_val", patterns: []string{"py_lib_*"}, want: true},
		{name: "glob star no match", rule: "js_lib_alias", patterns: []string{"py_lib_*"}, want: false},
		{name: "glob question match", rule: "py_a", patterns: []string{"py_?"}, want: true},
		{name: "glob question no match", rule: "py_ab", patterns: []string{"py_?"}, want: false},
		{name: "char class match", rule: "py_1", patterns: []string{"py_[0-9]"}, want: true},
		{name: "char class no match", rule: "py_a", patterns: []string{"py_[0-9]"}, want: false},
		{name: "multiple first matches", rule: "py_lib_alias_val", patterns: []string{"py_lib_alias_val", "other_*"}, want: true},
		{name: "multiple second matches", rule: "other_thing", patterns: []string{"py_*", "other_*"}, want: true},
		{name: "multiple none matches", rule: "js_thing", patterns: []string{"py_*", "other_*"}, want: false},
		{name: "empty rule name", rule: "", patterns: []string{"*"}, want: true},
		{name: "wildcard matches all", rule: "anything", patterns: []string{"*"}, want: true},
		{name: "empty pattern skipped", rule: "any", patterns: []string{"", "any"}, want: true},
		{name: "whitespace pattern skipped", rule: "any", patterns: []string{"   ", "any"}, want: true},
		{name: "trimmed pattern matches", rule: "py_lib_alias_val", patterns: []string{"  py_lib_alias_val  "}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ruleExcluded(tt.rule, tt.patterns)
			if got != tt.want {
				t.Errorf("ruleExcluded(%q, %v) = %v, want %v", tt.rule, tt.patterns, got, tt.want)
			}
		})
	}
}

// TestRuleExcluded_MalformedTreatedAsNoMatch documents the runtime contract:
// once ValidateIgnoreRules has approved the pattern list at startup, the
// matcher will not receive malformed patterns. If one leaks through anyway
// (e.g. a caller bypasses validation), ruleExcluded must not panic and must
// not silently match everything — it treats a per-pattern error as a
// non-match and continues.
func TestRuleExcluded_MalformedTreatedAsNoMatch(t *testing.T) {
	t.Parallel()
	// Sanity check: the pattern really is malformed.
	if _, err := filepath.Match("py_[abc", "py_a"); err == nil {
		t.Fatal("test premise broken: filepath.Match no longer errors on unclosed class")
	}
	// A malformed pattern followed by a valid non-matching pattern must not
	// cause ruleExcluded to return true (no silent match-all).
	if ruleExcluded("py_a", []string{"py_[abc", "no_match"}) {
		t.Errorf("expected no match, but ruleExcluded returned true on malformed pattern")
	}
	// A malformed pattern followed by a valid matching pattern still matches.
	if !ruleExcluded("py_a", []string{"py_[abc", "py_*"}) {
		t.Errorf("expected match via later valid pattern, ruleExcluded returned false")
	}
}

// TestValidateIgnoreRules_ErrorMessage ensures the validation error names
// the offending pattern so users can fix their CLI invocation.
func TestValidateIgnoreRules_ErrorMessage(t *testing.T) {
	t.Parallel()
	err := ValidateIgnoreRules([]string{"good", "bad_[abc"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "bad_[abc") {
		t.Errorf("expected error to name the offending pattern, got: %v", err)
	}
}
