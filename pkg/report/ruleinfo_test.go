// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/release"

	yarax "github.com/VirusTotal/yara-x/go"
)

func TestNewRuleInfo(t *testing.T) {
	t.Parallel()
	rules := reportRulesByName(t, map[string]string{
		"meta/format/elf_binary.yara": reportRuleSrc("meta_rule", "", "", "aaa"),
		"plain/rule.yara":             reportRuleSrc("plain_rule_name", "medium", "", "bbb"),
		"fp/override.yara": `
rule override_rule: override {
  meta:
    description  = "not a target"
    filetypes    = "elf"
    severity     = "low"
    path_include = "*.py"
    first        = "low"
    second       = "bogus"
  condition:
    true
}`,
		"fp/named.yara": `
rule named_rule {
  meta:
    first = "low"
  condition:
    true
}`,
	})

	tests := []struct {
		name         string
		rule         string
		wantMeta     bool
		wantMetaKey  string
		wantMetaVal  string
		wantFallback string
		wantOverride bool
		wantTargets  []overrideKey
	}{
		{name: "meta rule describes the file", rule: "meta_rule", wantMeta: true, wantMetaKey: "format", wantMetaVal: "elf_binary", wantFallback: "meta rule"},
		{name: "plain rule gets a description from its name", rule: "plain_rule_name", wantFallback: "plain rule name"},
		{
			name:         "override rule targets only unknown keys, scoring unknown levels as harmless",
			rule:         "override_rule",
			wantFallback: "override rule",
			wantOverride: true,
			wantTargets:  []overrideKey{{rule: "first", score: LOW}, {rule: "second", score: HARMLESS}},
		},
		{name: "rule without the override tag targets nothing", rule: "named_rule", wantFallback: "named rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := rules[tt.rule]
			if r == nil {
				t.Fatalf("rule %q not compiled", tt.rule)
			}
			ri := newRuleInfo(r, "", 7)
			if ri.order != 7 {
				t.Errorf("order: got = %d, want = %d", ri.order, 7)
			}
			if ri.isMeta != tt.wantMeta || ri.metaKey != tt.wantMetaKey || ri.metaValue != tt.wantMetaVal {
				t.Errorf("meta: got = %v %q=%q, want = %v %q=%q", ri.isMeta, ri.metaKey, ri.metaValue, tt.wantMeta, tt.wantMetaKey, tt.wantMetaVal)
			}
			if ri.fallbackDescription != tt.wantFallback {
				t.Errorf("fallbackDescription: got = %q, want = %q", ri.fallbackDescription, tt.wantFallback)
			}
			if ri.override != tt.wantOverride {
				t.Errorf("override: got = %v, want = %v", ri.override, tt.wantOverride)
			}
			if !reflect.DeepEqual(ri.targets, tt.wantTargets) {
				t.Errorf("targets: got = %+v, want = %+v", ri.targets, tt.wantTargets)
			}
			if ri.behavior.Override != nil || ri.behavior.MatchStrings != nil {
				t.Errorf("behavior: got Override = %q, MatchStrings = %q, want both nil", ri.behavior.Override, ri.behavior.MatchStrings)
			}
		})
	}
}

func TestRuleInfoDeclarationOrder(t *testing.T) {
	t.Parallel()
	yrs := compileTestRules(t, map[string]string{
		"b/second.yara": reportRuleSrc("b_rule", "", "", "bbb"),
		"a/first.yara":  reportRuleSrc("a_rule", "", "", "aaa") + reportRuleSrc("a_other", "", "", "aab"),
		"c/third.yara":  reportRuleSrc("c_rule", "", "", "ccc"),
	})
	infos := ruleInfosFor(yrs)
	if !infos.ordered() {
		t.Fatal("ordered: got = false, want = true")
	}
	for i, r := range yrs.Slice() {
		if got := infos.get(r).order; got != i {
			t.Errorf("%s order: got = %d, want = %d", r.Identifier(), got, i)
		}
	}
	if ruleInfosFor(nil).ordered() {
		t.Error("ordered without a rule set: got = true, want = false")
	}
}

// TestRuleInfosForCache checks that rule information is shared only between
// callers with the same rule set and rule URL ref, and that callers switching
// between rule sets keep their caches. It pins the ref, so it does not run in
// parallel.
func TestRuleInfosForCache(t *testing.T) {
	t.Cleanup(release.ResetRuleURLRef)
	src := map[string]string{"a/one.yara": reportRuleSrc("one", "", "", "x")}
	first := compileTestRules(t, src)
	second := compileTestRules(t, src)

	if got := ruleInfosFor(nil); got.cache != nil {
		t.Errorf("cache without a rule set: got = %p, want = nil", got.cache)
	}
	a := ruleInfosFor(first)
	if a.cache == nil {
		t.Fatal("cache for a rule set: got = nil")
	}
	if b := ruleInfosFor(first); b.cache != a.cache {
		t.Errorf("cache for the same rule set: got = %p, want = %p", b.cache, a.cache)
	}
	c := ruleInfosFor(second)
	if c.cache == a.cache {
		t.Errorf("cache for another rule set: got = %p, want a new cache", c.cache)
	}
	// Alternating between rule sets keeps both caches.
	if b := ruleInfosFor(first); b.cache != a.cache {
		t.Errorf("cache for the first rule set after the second: got = %p, want = %p", b.cache, a.cache)
	}
	release.PinRuleURLRef("v0.0.0-cache")
	if d := ruleInfosFor(second); d.cache == c.cache || d.ref != "v0.0.0-cache" {
		t.Errorf("cache after the ref changed: got = %p with ref %q, want a new cache with ref %q", d.cache, d.ref, "v0.0.0-cache")
	}
}

// TestGenerateRuleURLFollowsRef checks that cached rule URLs follow a change
// of the rule URL ref. It pins the ref, so it does not run in parallel.
func TestGenerateRuleURLFollowsRef(t *testing.T) {
	t.Cleanup(release.ResetRuleURLRef)
	yrs := compileTestRules(t, map[string]string{"test/ref.yara": reportRuleSrc("ref_rule", "high", "", "refmark")})
	fc := []byte("refmark")
	mrs := scanBuf(t, yrs, fc)
	for _, ref := range []string{"v1.0.0", "v2.0.0"} {
		release.PinRuleURLRef(ref)
		fr, err := Generate(t.Context(), "f", mrs, malcontent.Config{MinRisk: LOW, Rules: yrs}, "", nil, fc, int64(len(fc)), "cksum", nil, 0)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		want := "https://github.com/chainguard-dev/malcontent/blob/" + ref + "/rules/test/ref.yara#ref_rule"
		if len(fr.Behaviors) != 1 || fr.Behaviors[0].RuleURL != want {
			t.Errorf("RuleURL with ref %q: got = %+v, want one behavior with %q", ref, fr.Behaviors, want)
		}
	}
}

// TestRuleInfoCacheSlots checks that eight rule sets keep their cached rule
// information and that a ninth evicts the cache added first. Not parallel: it
// replaces every cache in the package-wide list.
func TestRuleInfoCacheSlots(t *testing.T) {
	src := map[string]string{"slots/rule.yara": reportRuleSrc("slot_rule", "", "", "slotmark")}
	sets := make([]*yarax.Rules, 9)
	for i := range sets {
		sets[i] = compileTestRules(t, src)
	}

	first := ruleInfosFor(sets[0]).cache
	for _, yrs := range sets[1:8] {
		ruleInfosFor(yrs)
	}
	if got := ruleInfosFor(sets[0]).cache; got != first {
		t.Errorf("cache of the first of eight rule sets: got = %p, want = %p", got, first)
	}
	ruleInfosFor(sets[8])
	if got := ruleInfosFor(sets[0]).cache; got == first {
		t.Errorf("cache of the first rule set after a ninth: got = %p, want a new cache", got)
	}
	// The caches hold the rule sets weakly, so keep them alive until here.
	runtime.KeepAlive(sets)
}

// TestRuleInfoAllocations checks the lookups Generate repeats for every
// match. Not parallel: testing.AllocsPerRun counts allocations process-wide.
func TestRuleInfoAllocations(t *testing.T) {
	yrs := compileTestRules(t, map[string]string{"alloc/rule.yara": reportRuleSrc("alloc_rule", "high", `description = "cached"`, "allocmark")})
	rule := yrs.Slice()[0]
	infos := ruleInfosFor(yrs)
	if first, again := infos.get(rule), infos.get(rule); again != first {
		t.Fatalf("second lookup: got = %p, want the cached %p", again, first)
	}
	var value any = "a metadata value"

	tests := []struct {
		name string
		run  func()
	}{
		{"cached rule information is returned without deriving it again", func() { infos.get(rule) }},
		{"string metadata renders without formatting", func() { _ = metaString(value) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(100, tt.run); got != 0 {
				t.Errorf("allocations per run: got = %v, want = 0", got)
			}
		})
	}
	runtime.KeepAlive(yrs)
}
