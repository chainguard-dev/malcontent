// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"io/fs"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/internal/yrx"
	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/release"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"

	yarax "github.com/VirusTotal/yara-x/go"
)

func TestNewRuleInfo(t *testing.T) {
	t.Parallel()
	byName := reportRulesByName(t, map[string]string{
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
		name            string
		rule            string
		wantMeta        bool
		wantMetaKey     string
		wantMetaVal     string
		wantDescription string
		wantOverride    bool
		wantTargets     []overrideKey
	}{
		{name: "meta rule describes the file", rule: "meta_rule", wantMeta: true, wantMetaKey: "format", wantMetaVal: "elf_binary", wantDescription: "meta rule"},
		{name: "plain rule gets a description from its name", rule: "plain_rule_name", wantDescription: "plain rule name"},
		{
			name:            "override rule targets only unknown keys and skips unknown levels",
			rule:            "override_rule",
			wantDescription: "not a target",
			wantOverride:    true,
			wantTargets:     []overrideKey{{rule: "first", score: LOW}},
		},
		{name: "rule without the override tag targets nothing", rule: "named_rule", wantDescription: "named rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := byName[tt.rule]
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
			if ri.behavior.Description != tt.wantDescription {
				t.Errorf("Description: got = %q, want = %q", ri.behavior.Description, tt.wantDescription)
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
		fr, err := Generate(t.Context(), "f", mrs, malcontent.Config{MinRisk: LOW, Rules: yrs}, "", fc, int64(len(fc)), "cksum", nil)
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

// problemRulesSrc declare rules whose tags or metadata reports cannot act on
// as written, beside rules that are fine.
var problemRulesSrc = map[string]string{
	"exec/shell/tags.yara": `
rule risk_tag: high { condition: true }
rule platform_tags: medium linux windows macos override_free { condition: true }
rule typo_tag: notamble { condition: true }
rule case_tag: High { condition: true }
rule untagged { condition: true }
`,
	"yara/vendor/rules.yar": `
rule vendor_tag: apt29 notamble { condition: true }
rule vendor_override: override {
  meta:
    some_rule = "hgih"
  condition:
    true
}
`,
	"false_positives/fp.yara": `
rule fp_good: override {
  meta:
    description = "fine"
    target      = "harmless"
  condition:
    true
}
rule fp_bad_level: override {
  meta:
    target = "hgih"
    other  = "medium"
  condition:
    true
}
rule fp_key_typo: override {
  meta:
    descriptions = "vulnerability.db"
  condition:
    true
}
`,
	"scope/ft.yara": `
rule ft_good {
  meta:
    filetypes = "elf,sh,jar,py,class,service"
  condition:
    true
}
rule ft_mime {
  meta:
    filetypes = "application/x-sh,zsh"
  condition:
    true
}
rule ft_image {
  meta:
    filetypes = "jpg,php"
  condition:
    true
}
rule ft_renamed {
  meta:
    filetypes = "dylib"
  condition:
    true
}
`,
}

func TestRuleInfoProblems(t *testing.T) {
	t.Parallel()
	byName := reportRulesByName(t, problemRulesSrc)
	tests := []struct {
		name        string
		rule        string
		want        []string
		wantTargets []overrideKey
	}{
		{name: "a risk tag is fine", rule: "risk_tag"},
		{name: "platform tags are fine but an unknown tag is reported", rule: "platform_tags", want: []string{`unknown tag "override_free"`}},
		{name: "a misspelled risk tag is reported", rule: "typo_tag", want: []string{`unknown tag "notamble"`}},
		{name: "a risk tag in the wrong case is reported", rule: "case_tag", want: []string{`unknown tag "High"`}},
		{name: "an untagged rule is fine", rule: "untagged"},
		{name: "third-party tags are free-form", rule: "vendor_tag"},
		{name: "third-party override metadata is not a directive", rule: "vendor_override"},
		{name: "an override with known levels is fine", rule: "fp_good", wantTargets: []overrideKey{{rule: "target", score: HARMLESS}}},
		{
			name:        "an override with an unknown level is reported and skipped",
			rule:        "fp_bad_level",
			want:        []string{`override of "target" has unknown risk level "hgih"`},
			wantTargets: []overrideKey{{rule: "other", score: MEDIUM}},
		},
		{name: "a misspelled metadata key on an override is reported", rule: "fp_key_typo", want: []string{`override of "descriptions" has unknown risk level "vulnerability.db"`}},
		{name: "known file types are fine", rule: "ft_good"},
		{name: "a MIME type is not a file type", rule: "ft_mime", want: []string{`unknown filetypes entry "application/x-sh"`}},
		{name: "a type malcontent never detects is reported", rule: "ft_image", want: []string{`unknown filetypes entry "jpg"`}},
		{name: "an extension that detection renames is reported", rule: "ft_renamed", want: []string{`unknown filetypes entry "dylib"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := byName[tt.rule]
			if r == nil {
				t.Fatalf("rule %q not compiled", tt.rule)
			}
			ri := newRuleInfo(r, "", 0)
			if !slices.Equal(ri.problems, tt.want) {
				t.Errorf("problems: got = %q, want = %q", ri.problems, tt.want)
			}
			if !reflect.DeepEqual(ri.targets, tt.wantTargets) {
				t.Errorf("targets: got = %+v, want = %+v", ri.targets, tt.wantTargets)
			}
		})
	}
}

// TestNewRuleInfoWarnsAboutProblems checks that deriving a rule logs each of
// its problems. Not parallel: it swaps the package's warning function.
func TestNewRuleInfoWarnsAboutProblems(t *testing.T) {
	byName := reportRulesByName(t, problemRulesSrc)
	var got []string
	prev := logWarn
	logWarn = func(msg string, args ...any) {
		parts := append(make([]string, 0, 1+len(args)), msg)
		for _, a := range args {
			parts = append(parts, fmt.Sprint(a))
		}
		got = append(got, strings.Join(parts, " "))
	}
	t.Cleanup(func() { logWarn = prev })

	tests := []struct {
		name string
		rule string
		want []string
	}{
		{"a rule without problems logs nothing", "risk_tag", nil},
		{"each problem is logged with its rule", "fp_bad_level", []string{`Rule metadata problem rule false_positives/fp.yara:fp_bad_level problem override of "target" has unknown risk level "hgih"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got = nil
			newRuleInfo(byName[tt.rule], "", 0)
			if !slices.Equal(got, tt.want) {
				t.Errorf("warnings: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestRuleCorpusHasNoMetadataProblems keeps the bundled rules free of tags,
// override levels, and file types that reports cannot act on.
func TestRuleCorpusHasNoMetadataProblems(t *testing.T) {
	t.Parallel()
	yrs, err := compile.Recursive(t.Context(), []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	t.Cleanup(func() { yrx.Destroy(yrs) })
	for _, r := range yrs.Slice() {
		if ri := newRuleInfo(r, "", 0); len(ri.problems) > 0 {
			t.Errorf("%s:%s: %q", r.Namespace(), r.Identifier(), ri.problems)
		}
	}
}
