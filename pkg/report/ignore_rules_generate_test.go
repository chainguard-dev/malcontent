// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"sort"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"

	yarax "github.com/VirusTotal/yara-x/go"
)

// compileTestRules compiles a set of YARA rule sources, each in its own
// namespace so generateKey produces distinct keys per rule (matching how
// the production compile pipeline in pkg/compile assigns namespaces per
// source file). Without distinct namespaces, updateBehavior would dedupe
// all matches into a single entry keyed by the empty string, which is not
// the behavior we want to test.
func compileTestRules(t *testing.T, sources map[string]string) *yarax.Rules {
	t.Helper()
	c, err := yarax.NewCompiler()
	if err != nil {
		t.Fatalf("NewCompiler: %v", err)
	}
	// Sort keys for a deterministic namespace-creation order so tests
	// remain reproducible across Go versions.
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, ns := range names {
		c.NewNamespace(ns)
		if err := c.AddSource(sources[ns], yarax.WithOrigin(ns)); err != nil {
			t.Fatalf("AddSource(%q): %v", ns, err)
		}
	}
	r := c.Build()
	t.Cleanup(func() { r.Destroy() })
	return r
}

// scan runs the compiled rules over a byte buffer and returns ScanResults.
func scanBuf(t *testing.T, rules *yarax.Rules, data []byte) *yarax.ScanResults {
	t.Helper()
	scanner := yarax.NewScanner(rules)
	t.Cleanup(func() { scanner.Destroy() })
	res, err := scanner.Scan(data)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

// behaviorNames returns the sorted set of rule names present in a
// FileReport's Behaviors slice.
func behaviorNames(fr *malcontent.FileReport) map[string]struct{} {
	names := make(map[string]struct{}, len(fr.Behaviors))
	for _, b := range fr.Behaviors {
		names[b.RuleName] = struct{}{}
	}
	return names
}

var testRulesSrc = map[string]string{
	"aliasval": `
rule py_lib_alias_val: medium {
  strings:
    $a = "aaa"
  condition:
    $a
}`,
	"other": `
rule py_lib_other: high {
  strings:
    $b = "bbb"
  condition:
    $b
}`,
	"jsthing": `
rule js_thing: low {
  strings:
    $c = "ccc"
  condition:
    $c
}`,
}

func TestGenerate_IgnoreRules(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, testRulesSrc)
	fc := []byte("aaa bbb ccc")
	mrs := scanBuf(t, rules, fc)

	tests := []struct {
		name         string
		ignoreRules  []string
		wantPresent  []string
		wantAbsent   []string
		wantRiskZero bool
	}{
		{
			name:        "no filter keeps all",
			ignoreRules: nil,
			wantPresent: []string{"py_lib_alias_val", "py_lib_other", "js_thing"},
		},
		{
			name:        "empty slice keeps all",
			ignoreRules: []string{},
			wantPresent: []string{"py_lib_alias_val", "py_lib_other", "js_thing"},
		},
		{
			name:        "exact excludes one",
			ignoreRules: []string{"py_lib_alias_val"},
			wantPresent: []string{"py_lib_other", "js_thing"},
			wantAbsent:  []string{"py_lib_alias_val"},
		},
		{
			name:        "glob excludes py_lib prefix",
			ignoreRules: []string{"py_lib_*"},
			wantPresent: []string{"js_thing"},
			wantAbsent:  []string{"py_lib_alias_val", "py_lib_other"},
		},
		{
			name:        "multiple exact",
			ignoreRules: []string{"py_lib_alias_val", "js_thing"},
			wantPresent: []string{"py_lib_other"},
			wantAbsent:  []string{"py_lib_alias_val", "js_thing"},
		},
		{
			name:         "exclude all",
			ignoreRules:  []string{"*"},
			wantAbsent:   []string{"py_lib_alias_val", "py_lib_other", "js_thing"},
			wantRiskZero: true,
		},
		{
			name:        "non-matching pattern is no-op",
			ignoreRules: []string{"never_matches_*"},
			wantPresent: []string{"py_lib_alias_val", "py_lib_other", "js_thing"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := malcontent.Config{
				IgnoreRules: tt.ignoreRules,
				MinRisk:     -1, // include harmless
			}
			fr, err := Generate(t.Context(), "test/path", mrs, c, "", clog.New(nil), fc, int64(len(fc)), "cksum", nil, 0)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			names := behaviorNames(fr)
			for _, want := range tt.wantPresent {
				if _, ok := names[want]; !ok {
					t.Errorf("expected %q in Behaviors, absent (got %v)", want, names)
				}
			}
			for _, dontWant := range tt.wantAbsent {
				if _, ok := names[dontWant]; ok {
					t.Errorf("expected %q to be excluded from Behaviors, present", dontWant)
				}
			}
			if tt.wantRiskZero && fr.RiskScore != 0 {
				t.Errorf("expected RiskScore 0 after excluding all, got %d", fr.RiskScore)
			}
		})
	}
}

// TestGenerate_IgnoreRules_RiskRecomputes verifies that excluding the
// highest-risk rule drops the file's overall risk score to the next
// remaining rule's score, rather than keeping the excluded rule's
// contribution. This is the reason the exclusion check runs before risk
// accumulation in Generate.
func TestGenerate_IgnoreRules_RiskRecomputes(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, testRulesSrc)
	fc := []byte("aaa bbb ccc")
	mrs := scanBuf(t, rules, fc)

	// Baseline: no exclusion, highest is HIGH from py_lib_other.
	baseline, err := Generate(t.Context(), "test/path", mrs,
		malcontent.Config{MinRisk: -1}, "", clog.New(nil),
		fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("baseline Generate: %v", err)
	}
	if baseline.RiskScore < HIGH {
		t.Fatalf("baseline risk should be >= HIGH, got %d", baseline.RiskScore)
	}

	// Exclude the HIGH rule; remaining are medium and low. Risk drops.
	filtered, err := Generate(t.Context(), "test/path", mrs,
		malcontent.Config{
			IgnoreRules: []string{"py_lib_other"},
			MinRisk:     -1,
		}, "", clog.New(nil),
		fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("filtered Generate: %v", err)
	}
	if filtered.RiskScore >= baseline.RiskScore {
		t.Errorf("excluding highest-risk rule should lower RiskScore: baseline=%d filtered=%d",
			baseline.RiskScore, filtered.RiskScore)
	}
	if filtered.RiskScore != MEDIUM {
		t.Errorf("expected MEDIUM (%d) after excluding HIGH rule, got %d", MEDIUM, filtered.RiskScore)
	}
}

// overrideRulesSrc defines a rule whose behavior can be downgraded via
// an override rule. The names are contrived so we can exercise:
//
//	(a) excluding a rule that the override targets — the override should
//	    have no effect, but must not panic.
//	(b) excluding the override rule itself — the base rule's original
//	    risk should survive unchanged.
var overrideRulesSrc = map[string]string{
	"base": `
rule base_high_rule: high {
  strings:
    $a = "aaa"
  condition:
    $a
}`,
	"downgrade": `
rule downgrade_it: override {
  meta:
    base_high_rule = "low"
  strings:
    $a = "aaa"
  condition:
    $a
}`,
}

func TestGenerate_IgnoreRules_OverrideExcludingTarget(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, overrideRulesSrc)
	fc := []byte("aaa")
	mrs := scanBuf(t, rules, fc)

	// Excluding the base rule the override targets: the override rule loses
	// its subject. Must not panic; the report should not contain base_high_rule.
	fr, err := Generate(t.Context(), "test/path", mrs,
		malcontent.Config{
			IgnoreRules: []string{"base_high_rule"},
			MinRisk:     -1,
		}, "", clog.New(nil),
		fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	names := behaviorNames(fr)
	if _, present := names["base_high_rule"]; present {
		t.Errorf("expected base_high_rule to be excluded, still present in %v", names)
	}
}

// nameVsPathRulesSrc pins down the "rule name is independent of the file
// name / namespace" contract. Each rule lives in a namespace whose name
// includes a keyword (e.g. "python") that the rule identifier itself does
// NOT contain. This mirrors the maintainer's point: a rule declared in
// rules/anti-static/obfuscation/python.yara can have any identifier —
// filtering must match the identifier, never the namespace/file path.
// Distinct namespaces per rule so generateKey produces distinct keys and
// updateBehavior does not collapse siblings during dedup.
var nameVsPathRulesSrc = map[string]string{
	// The namespace-side keywords ("python", "python.yara") are what a
	// path-oriented matcher would latch onto. None of these strings appear
	// in the rule identifiers below.
	"python.yara":         `rule obfuscation_check: medium { strings: $a = "aaa" condition: $a }`,
	"python_helpers.yara": `rule wallet_stealer: critical { strings: $b = "bbb" condition: $b }`,
	"js/other.yara":       `rule third_rule: high { strings: $c = "ccc" condition: $c }`,
}

// TestGenerate_IgnoreRules_MatchesRuleNameNotFilename verifies that
// filepath.Match is applied to the YARA rule identifier (m.Identifier()),
// never to the source file/namespace path. Patterns that would match
// namespaces ("*python*", "python.yara", "python") must exclude no rules
// because none of the rule identifiers contain "python".
func TestGenerate_IgnoreRules_MatchesRuleNameNotFilename(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, nameVsPathRulesSrc)
	fc := []byte("aaa bbb ccc")
	mrs := scanBuf(t, rules, fc)

	c := malcontent.Config{
		IgnoreRules: []string{"*python*", "python.yara", "python"},
		MinRisk:     -1,
	}
	fr, err := Generate(t.Context(), "test/path", mrs, c, "", clog.New(nil),
		fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	names := behaviorNames(fr)
	for _, expect := range []string{"obfuscation_check", "wallet_stealer", "third_rule"} {
		if _, ok := names[expect]; !ok {
			t.Errorf("expected %q to survive (patterns match namespaces, not identifiers); got %v",
				expect, names)
		}
	}
}

// TestGenerate_IgnoreRules_MatchesByNameEvenWhenNameDiffersFromFile
// verifies that when the rule name differs from the source file/namespace
// name, the rule can still be excluded by its identifier. The
// "wallet_stealer" rule lives in "python_helpers.yara" but is identified
// as "wallet_stealer"; the exclusion must fire on the identifier.
func TestGenerate_IgnoreRules_MatchesByNameEvenWhenNameDiffersFromFile(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, nameVsPathRulesSrc)
	fc := []byte("aaa bbb ccc")
	mrs := scanBuf(t, rules, fc)

	c := malcontent.Config{
		IgnoreRules: []string{"wallet_stealer"},
		MinRisk:     -1,
	}
	fr, err := Generate(t.Context(), "test/path", mrs, c, "", clog.New(nil),
		fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	names := behaviorNames(fr)
	if _, present := names["wallet_stealer"]; present {
		t.Errorf("expected wallet_stealer excluded by name, still present in %v", names)
	}
	for _, expect := range []string{"obfuscation_check", "third_rule"} {
		if _, ok := names[expect]; !ok {
			t.Errorf("expected %q to survive; got %v", expect, names)
		}
	}
}

// multiInFileRulesSrc: three rules in ONE namespace with distinct risks.
// Because generateKey keys by namespace path (not by identifier), all
// three collapse in updateBehavior to a single behavior — the highest-risk
// one wins. This test proves that IgnoreRules operates on identifiers by
// showing that excluding the current-winner rule causes the next-highest
// rule to become the winner. If IgnoreRules mistakenly matched on
// namespace, either all three rules would be excluded (returning zero
// behaviors) or none would (returning the original winner unchanged).
var multiInFileRulesSrc = map[string]string{
	"anti-static/obfuscation/python.yara": `
rule py_lib_alias_val: medium {
  strings:
    $a = "aaa"
  condition:
    $a
}

rule py_dynamic_require: high {
  strings:
    $b = "bbb"
  condition:
    $b
}

rule py_eval_marshal: critical {
  strings:
    $c = "ccc"
  condition:
    $c
}`,
}

// TestGenerate_IgnoreRules_MultipleRulesInOneFileOnlyOneExcluded pins down
// the maintainer's requirement: multiple rules can live in one file, and a
// glob targeting a specific identifier must exclude only that rule.
// Because rules in a single .yara file collapse to one behavior entry
// (keyed by file path), we observe correctness through the surviving
// entry's RuleName field: excluding the top-risk rule shifts the winner
// to the next-highest.
func TestGenerate_IgnoreRules_MultipleRulesInOneFileOnlyOneExcluded(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, multiInFileRulesSrc)
	fc := []byte("aaa bbb ccc")
	mrs := scanBuf(t, rules, fc)

	// Baseline: without exclusion, the critical rule wins the dedup.
	baseline, err := Generate(t.Context(), "test/path", mrs,
		malcontent.Config{MinRisk: -1}, "", clog.New(nil),
		fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("baseline Generate: %v", err)
	}
	if len(baseline.Behaviors) != 1 {
		t.Fatalf("baseline: expected 1 behavior (dedup by namespace), got %d: %v",
			len(baseline.Behaviors), behaviorNames(baseline))
	}
	if baseline.Behaviors[0].RuleName != "py_eval_marshal" {
		t.Fatalf("baseline: expected winner py_eval_marshal, got %q", baseline.Behaviors[0].RuleName)
	}

	// Exclude the winner by identifier: py_dynamic_require should become
	// the new winner. This proves the exclusion decided on identifier —
	// if it had matched by namespace "anti-static/obfuscation/python", it
	// would have excluded all three rules.
	filtered, err := Generate(t.Context(), "test/path", mrs,
		malcontent.Config{
			IgnoreRules: []string{"py_eval_marshal"},
			MinRisk:     -1,
		}, "", clog.New(nil),
		fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("filtered Generate: %v", err)
	}
	if len(filtered.Behaviors) != 1 {
		t.Fatalf("filtered: expected 1 behavior (sibling rules still match), got %d: %v",
			len(filtered.Behaviors), behaviorNames(filtered))
	}
	if filtered.Behaviors[0].RuleName != "py_dynamic_require" {
		t.Errorf("filtered: expected next-highest winner py_dynamic_require, got %q (all-three-excluded would drop to zero behaviors, none-excluded would keep py_eval_marshal)",
			filtered.Behaviors[0].RuleName)
	}

	// Exclude the top two: py_lib_alias_val should be the sole survivor.
	filtered2, err := Generate(t.Context(), "test/path", mrs,
		malcontent.Config{
			IgnoreRules: []string{"py_eval_marshal", "py_dynamic_require"},
			MinRisk:     -1,
		}, "", clog.New(nil),
		fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("filtered2 Generate: %v", err)
	}
	if len(filtered2.Behaviors) != 1 || filtered2.Behaviors[0].RuleName != "py_lib_alias_val" {
		t.Errorf("filtered2: expected sole survivor py_lib_alias_val, got %v", behaviorNames(filtered2))
	}
}

func TestGenerate_IgnoreRules_OverrideExcludingOverride(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, overrideRulesSrc)
	fc := []byte("aaa")
	mrs := scanBuf(t, rules, fc)

	// Excluding the override rule itself: the base rule retains its
	// original (HIGH) risk rather than being downgraded to LOW.
	fr, err := Generate(t.Context(), "test/path", mrs,
		malcontent.Config{
			IgnoreRules: []string{"downgrade_it"},
			MinRisk:     -1,
		}, "", clog.New(nil),
		fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var base *malcontent.Behavior
	for _, b := range fr.Behaviors {
		if b.RuleName == "base_high_rule" {
			base = b
			break
		}
	}
	if base == nil {
		t.Fatalf("expected base_high_rule in Behaviors, got %v", behaviorNames(fr))
	}
	if base.RiskScore != HIGH {
		t.Errorf("expected base_high_rule to retain HIGH risk when override is excluded, got %d", base.RiskScore)
	}
}
