// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"

	yarax "github.com/VirusTotal/yara-x/go"
)

// reportRulesByName compiles sources (one namespace per key) and indexes the
// resulting rules, with their namespace, tags, and metadata, by identifier.
func reportRulesByName(t *testing.T, sources map[string]string) map[string]*yarax.Rule {
	t.Helper()
	byName := map[string]*yarax.Rule{}
	for _, r := range compileTestRules(t, sources).Slice() {
		byName[r.Identifier()] = r
	}
	return byName
}

// reportRuleSrc returns a rule matching literal, with optional space-separated
// tags and a single optional meta assignment.
func reportRuleSrc(name, tags, meta, literal string) string {
	head := "rule " + name
	if tags != "" {
		head += ": " + tags
	}
	body := ""
	if meta != "" {
		body = "  meta:\n    " + meta + "\n"
	}
	return fmt.Sprintf("%s {\n%s  strings:\n    $s = %q\n  condition:\n    $s\n}\n", head, body, literal)
}

// reportGenerate scans fc with the compiled sources and returns the report.
func reportGenerate(t *testing.T, sources map[string]string, fc []byte, path string, c malcontent.Config, kind *programkind.FileType) *malcontent.FileReport {
	t.Helper()
	mrs := scanBuf(t, compileTestRules(t, sources), fc)
	fr, err := Generate(t.Context(), path, mrs, c, "", nil, fc, int64(len(fc)), "cksum", kind, 0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return fr
}

func reportSortedNames(fr *malcontent.FileReport) []string {
	return slices.Sorted(maps.Keys(behaviorNames(fr)))
}

func TestFileMatchesRuleScoping(t *testing.T) {
	t.Parallel()
	rules := reportRulesByName(t, map[string]string{"scope/rules": `
rule ft_elf {
  meta:
    filetypes = "elf,macho"
  condition:
    true
}

rule inc_py {
  meta:
    path_include = "*.py,*/setup.py"
  condition:
    true
}

rule exc_dist {
  meta:
    path_exclude = "dist/*"
  condition:
    true
}

rule inc_setup {
  meta:
    path_include = "*/setup.py"
  condition:
    true
}

rule inc_js_exc_dist {
  meta:
    path_include = "*.js"
    path_exclude = "dist/*"
  condition:
    true
}

rule unscoped {
  condition:
    true
}
`})

	tests := []struct {
		name string
		rule string
		ext  string
		path string
		want bool
	}{
		{"filetypes match the detected type", "ft_elf", "elf", "bin/tool", true},
		{"filetypes reject another detected type", "ft_elf", "py", "bin/tool.py", false},
		{"filetypes treat an undetected type as universal", "ft_elf", "", "bin/tool", true},
		{"path_include matches the path", "inc_py", "", "pkg/mod.py", true},
		{"path_include rejects another path", "inc_py", "", "pkg/mod.js", false},
		{"path_include accepts the detected type of an extensionless file", "inc_py", "py", "pkg/script", true},
		{"path_include rejects another detected type of an extensionless file", "inc_py", "js", "pkg/script", false},
		{"path_include is ignored without a path", "inc_py", "", "", true},
		{"path_include without extension globs matches its path", "inc_setup", "", "pkg/setup.py", true},
		{"path_include without extension globs rejects another path of an undetected type", "inc_setup", "", "pkg/mod.py", false},
		{"path_exclude rejects a matching path", "exc_dist", "", "repo/dist/app.js", false},
		{"path_exclude keeps another path", "exc_dist", "", "repo/src/app.js", true},
		{"path_exclude is ignored without a path", "exc_dist", "", "", true},
		{"path_exclude wins over path_include", "inc_js_exc_dist", "", "repo/dist/app.js", false},
		{"path_include with an exclusion keeps other matches", "inc_js_exc_dist", "", "repo/src/app.js", true},
		{"unscoped rule applies everywhere", "unscoped", "py", "pkg/mod.py", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := rules[tt.rule]
			if r == nil {
				t.Fatalf("rule %q not compiled", tt.rule)
			}
			scope := newRuleScope(r.Metadata())
			if got := scope.matches(tt.ext, tt.path); got != tt.want {
				t.Errorf("scope of %s matches(%q, %q): got = %v, want = %v", tt.rule, tt.ext, tt.path, got, tt.want)
			}
		})
	}
}

var reportMetadataRulesSrc = map[string]string{
	"first/party": `
rule target {
  condition:
    true
}

rule author_with_url {
  meta:
    author = "Arnim Rupp (https://github.com/ruppde)"
  condition:
    true
}

rule author_plain {
  meta:
    author = "Jane Doe"
  condition:
    true
}

rule author_handle {
  meta:
    author = "@janedoe"
  condition:
    true
}

rule author_fediverse {
  meta:
    author = "@janedoe@infosec.exchange"
  condition:
    true
}

rule author_bad_url {
  meta:
    author = "Jane (http://exa mple.com)"
  condition:
    true
}

rule known_keys {
  meta:
    author_url  = "https://example.com/author"
    license     = "Apache-2.0"
    license_url = "https://example.com/license"
    reference   = "https://example.com/ref one"
    source_url  = "https://example.com/src two"
    pledge      = "inet"
    syscall     = "socket,connect"
    cap         = "CAP_NET_RAW"
  condition:
    true
}

rule desc_equal_length {
  meta:
    description = "abc"
    name        = "xyz"
  condition:
    true
}

rule desc_longer {
  meta:
    description = "short"
    threat_name = "a longer threat name"
  condition:
    true
}

rule desc_threat_hunting {
  meta:
    description = "Detection patterns for the tool 'AnyDesk' taken from the ThreatHunting-Keywords github project"
  condition:
    true
}

rule empty_values {
  meta:
    source_url  = ""
    pledge      = ""
    description = "kept after empty values"
  condition:
    true
}

rule self_marker {
  meta:
    __malcontent__ = "true"
  condition:
    true
}

rule self_marker_false {
  meta:
    __malcontent__ = "false"
  condition:
    true
}

rule override_target: override {
  meta:
    target = "medium"
  condition:
    true
}

rule named_target {
  meta:
    target = "medium"
  condition:
    true
}

rule other_target {
  condition:
    true
}

rule override_mixed: override {
  meta:
    target       = "medium"
    other_target = "low"
  condition:
    true
}

rule override_missing_first: override {
  meta:
    missing_rule = "low"
    target       = "medium"
  condition:
    true
}

rule override_scoped: override {
  meta:
    filetypes    = "py"
    severity     = "low"
    path_include = "*.py"
    target       = "low"
  condition:
    true
}

rule unknown_keys {
  meta:
    version = "1.0"
    date    = "2024-01-01"
  condition:
    true
}
`,
	"yara/vendor/rules.yar": `
rule vendor_override: override {
  meta:
    target = "low"
  condition:
    true
}

rule vendor_override_partial: override {
  meta:
    target       = "low"
    missing_rule = "low"
  condition:
    true
}
`,
}

func TestReportBuilderBehavior(t *testing.T) {
	t.Parallel()
	rules := reportRulesByName(t, reportMetadataRulesSrc)
	const ref = "v0.0.0-test"

	// matching lists the identifiers of the rules that matched the file; edit
	// applies the expected changes to the behavior the rule starts from.
	tests := []struct {
		name           string
		rule           string
		matching       []string
		edit           func(b *malcontent.Behavior)
		wantInvalid    bool
		wantTargets    map[string]int
		wantMalcontent bool
		wantPledges    []string
		wantSyscalls   []string
		wantCaps       []string
	}{
		{
			name: "author with URL splits name and link",
			rule: "author_with_url",
			edit: func(b *malcontent.Behavior) {
				b.RuleAuthor = "Arnim Rupp"
				b.RuleAuthorURL = "https://github.com/ruppde"
			},
		},
		{
			name: "plain author is kept verbatim",
			rule: "author_plain",
			edit: func(b *malcontent.Behavior) { b.RuleAuthor = "Jane Doe" },
		},
		{
			name: "author handle loses its at sign",
			rule: "author_handle",
			edit: func(b *malcontent.Behavior) { b.RuleAuthor = "janedoe" },
		},
		{
			name: "author handle keeps a later at sign",
			rule: "author_fediverse",
			edit: func(b *malcontent.Behavior) { b.RuleAuthor = "janedoe@infosec.exchange" },
		},
		{
			name: "author with malformed URL is kept verbatim",
			rule: "author_bad_url",
			edit: func(b *malcontent.Behavior) { b.RuleAuthor = "Jane (http://exa mple.com)" },
		},
		{
			name: "known keys populate behavior fields and capability lists",
			rule: "known_keys",
			edit: func(b *malcontent.Behavior) {
				b.RuleAuthorURL = "https://example.com/author"
				b.RuleLicense = "Apache-2.0"
				b.RuleLicenseURL = "https://example.com/license"
				b.ReferenceURL = "https://example.com/ref%20one"
				b.RuleURL = "https://example.com/src%20two"
			},
			wantPledges:  []string{"inet"},
			wantSyscalls: []string{"socket", "connect"},
			wantCaps:     []string{"CAP_NET_RAW"},
		},
		{
			name: "equal-length descriptions keep the first",
			rule: "desc_equal_length",
			edit: func(b *malcontent.Behavior) { b.Description = "abc" },
		},
		{
			name: "longer description wins",
			rule: "desc_longer",
			edit: func(b *malcontent.Behavior) { b.Description = "a longer threat name" },
		},
		{
			name: "threat hunting description is shortened",
			rule: "desc_threat_hunting",
			edit: func(b *malcontent.Behavior) { b.Description = `references "AnyDesk" tool` },
		},
		{
			name: "empty values are ignored and later keys still parse",
			rule: "empty_values",
			edit: func(b *malcontent.Behavior) { b.Description = "kept after empty values" },
		},
		{
			name:           "malcontent marker set to true flags the file",
			rule:           "self_marker",
			wantMalcontent: true,
		},
		{
			name: "malcontent marker set to false leaves the file unflagged",
			rule: "self_marker_false",
		},
		{
			name:     "override of a matching rule applies its severity",
			rule:     "override_target",
			matching: []string{"target"},
			edit: func(b *malcontent.Behavior) {
				b.RiskScore = MEDIUM
				b.RiskLevel = LevelMEDIUM
				b.Override = []string{"target"}
			},
			wantTargets: map[string]int{"target": MEDIUM},
		},
		{
			// The override rule's own behavior is dropped in handleOverrides.
			// Each target carries the severity of its own key.
			name:     "override records each key with its own severity",
			rule:     "override_mixed",
			matching: []string{"target", "other_target"},
			edit: func(b *malcontent.Behavior) {
				b.RiskScore = LOW
				b.RiskLevel = LevelLOW
				b.Override = []string{"target", "other_target"}
			},
			wantTargets: map[string]int{"target": MEDIUM, "other_target": LOW},
		},
		{
			name:        "override of a rule that did not match is invalid",
			rule:        "override_target",
			wantInvalid: true,
		},
		{
			name:     "override naming a missing rule first still records a later matching rule",
			rule:     "override_missing_first",
			matching: []string{"target"},
			edit: func(b *malcontent.Behavior) {
				b.RiskScore = MEDIUM
				b.RiskLevel = LevelMEDIUM
				b.Override = []string{"target"}
			},
			wantInvalid: true,
			wantTargets: map[string]int{"target": MEDIUM},
		},
		{
			name:     "override skips scoping and severity keys",
			rule:     "override_scoped",
			matching: []string{"target"},
			edit: func(b *malcontent.Behavior) {
				b.RiskScore = LOW
				b.RiskLevel = LevelLOW
				b.Override = []string{"target"}
			},
			wantTargets: map[string]int{"target": LOW},
		},
		{
			name:     "third-party override is not applied",
			rule:     "vendor_override",
			matching: []string{"target"},
		},
		{
			name:        "third-party override naming a missing rule after a matching one is invalid",
			rule:        "vendor_override_partial",
			matching:    []string{"target"},
			wantInvalid: true,
		},
		{
			name:     "non-override rule naming a matching rule is not an override",
			rule:     "named_target",
			matching: []string{"target"},
		},
		{
			name: "unknown keys on a non-override rule are ignored",
			rule: "unknown_keys",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := rules[tt.rule]
			if r == nil {
				t.Fatalf("rule %q not compiled", tt.rule)
			}
			matching := make([]*yarax.Rule, 0, len(tt.matching))
			for _, n := range tt.matching {
				matching = append(matching, rules[n])
			}
			risk := matchRisk(r)
			want := malcontent.Behavior{
				ID:        generateKey(r.Namespace(), r.Identifier()),
				RuleName:  tt.rule,
				RuleURL:   generateRuleURL(ref, r.Namespace(), r.Identifier()),
				RiskScore: risk,
				RiskLevel: RiskLevels[risk],
			}
			if tt.edit != nil {
				tt.edit(&want)
			}
			ri := newRuleInfo(r, ref, 0)
			rb := newReportBuilder(&malcontent.FileReport{}, nil, matching)

			b, valid := rb.behavior(ri)
			fr, overrides := rb.fr, rb.overrides
			pledges, caps, syscalls := rb.pledges, rb.caps, rb.syscalls

			if valid == tt.wantInvalid {
				t.Errorf("valid: got = %v, want = %v", valid, !tt.wantInvalid)
			}
			if !reflect.DeepEqual(*b, want) {
				t.Errorf("behavior: got = %+v, want = %+v", *b, want)
			}
			gotTargets := map[string]int{}
			for _, o := range overrides {
				if o.rule != b {
					t.Errorf("override %q source: got = %p, want = %p", o.target, o.rule, b)
				}
				gotTargets[o.target] = o.score
			}
			if !maps.Equal(gotTargets, tt.wantTargets) {
				t.Errorf("override targets: got = %v, want = %v", gotTargets, tt.wantTargets)
			}
			if len(fr.Overrides) != 0 {
				t.Errorf("fr.Overrides: got = %d entries, want = 0", len(fr.Overrides))
			}
			if fr.IsMalcontent != tt.wantMalcontent {
				t.Errorf("IsMalcontent: got = %v, want = %v", fr.IsMalcontent, tt.wantMalcontent)
			}
			if !slices.Equal(pledges, tt.wantPledges) {
				t.Errorf("pledges: got = %q, want = %q", pledges, tt.wantPledges)
			}
			if !slices.Equal(syscalls, tt.wantSyscalls) {
				t.Errorf("syscalls: got = %q, want = %q", syscalls, tt.wantSyscalls)
			}
			if !slices.Equal(caps, tt.wantCaps) {
				t.Errorf("caps: got = %q, want = %q", caps, tt.wantCaps)
			}
		})
	}
}

func TestMatchRiskSeverityDriven(t *testing.T) {
	t.Parallel()
	rules := reportRulesByName(t, map[string]string{
		"yara/guarddog/rules.yar": `
rule gd_declared_low {
  meta:
    description = "capability style rule"
    severity    = "low"
  condition:
    true
}

rule gd_declared_uppercase {
  meta:
    severity = "MEDIUM"
  condition:
    true
}

rule threat_process_cryptomining {
  meta:
    severity = "high"
  condition:
    true
}

rule gd_unknown_severity {
  meta:
    severity = "extreme"
  condition:
    true
}

rule gd_no_severity {
  meta:
    description = "no severity declared"
  condition:
    true
}

rule gd_level_word_in_another_key {
  meta:
    description = "low"
  condition:
    true
}
`,
		"yara/elastic/rules.yar": `
rule elastic_declared_low {
  meta:
    severity = "low"
  condition:
    true
}
`,
	})

	tests := []struct {
		name string
		rule string
		want int
	}{
		{"declared severity after other keys is honored", "gd_declared_low", LOW},
		{"declared severity is case-insensitive", "gd_declared_uppercase", MEDIUM},
		{"re-weighted rule uses the override table", "threat_process_cryptomining", MEDIUM},
		{"unknown severity falls back to namespace risk", "gd_unknown_severity", HIGH},
		{"missing severity falls back to namespace risk", "gd_no_severity", HIGH},
		{"a level in another key is not a severity", "gd_level_word_in_another_key", HIGH},
		{"severity is ignored for sources that do not opt in", "elastic_declared_low", CRITICAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := rules[tt.rule]
			if r == nil {
				t.Fatalf("rule %q not compiled", tt.rule)
			}
			if got := matchRisk(r); got != tt.want {
				t.Errorf("matchRisk(%s): got = %d, want = %d", tt.rule, got, tt.want)
			}
		})
	}
}

func TestHighestMatchRisk(t *testing.T) {
	t.Parallel()
	// The unscoped rule sits between two scoped rules so a scoped rule is
	// evaluated first regardless of match order.
	rules := compileTestRules(t, map[string]string{
		"a/scoped": reportRuleSrc("a_scoped_critical", "critical", `filetypes = "elf"`, "aaa"),
		"b/plain":  reportRuleSrc("b_plain_medium", "medium", "", "bbb"),
		"c/scoped": reportRuleSrc("c_scoped_critical", "critical", `filetypes = "elf"`, "ccc"),
	})
	hit := scanBuf(t, rules, []byte("aaa bbb ccc"))
	single := scanBuf(t, rules, []byte("bbb"))
	miss := scanBuf(t, rules, []byte("zzz"))

	tests := []struct {
		name string
		mrs  *yarax.ScanResults
		kind *programkind.FileType
		want int
	}{
		{"scoped rules are excluded for another file type", hit, &programkind.FileType{Ext: "py"}, MEDIUM},
		{"scoped rules count for their file type", hit, &programkind.FileType{Ext: "elf"}, CRITICAL},
		{"unknown file type keeps scoped rules", hit, nil, CRITICAL},
		{"no matches yields zero", miss, &programkind.FileType{Ext: "elf"}, 0},
		{"a single match counts", single, nil, MEDIUM},
		{"missing scan results yield zero", nil, &programkind.FileType{Ext: "elf"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := HighestMatchRisk(tt.mrs, tt.kind, "bin/sample", "", malcontent.Config{}); got != tt.want {
				t.Errorf("HighestMatchRisk: got = %d, want = %d", got, tt.want)
			}
		})
	}
}

func TestGenerateBehaviorFields(t *testing.T) {
	t.Parallel()
	fc := []byte("alpha bravo charlie")
	fr := reportGenerate(t, map[string]string{
		"alpha/one":     reportRuleSrc("alpha_rule", "low", `description = "alpha description"`, "alpha"),
		"bravo/two":     reportRuleSrc("bravo_rule", "medium", "", "bravo"),
		"charlie/three": reportRuleSrc("charlie_rule", "high", "", "charlie"),
	}, fc, "test/path", malcontent.Config{MinRisk: LOW}, nil)

	type view struct {
		ID           string
		RuleName     string
		Description  string
		RiskScore    int
		RiskLevel    string
		MatchStrings []string
	}
	want := []view{
		{ID: "alpha/one", RuleName: "alpha_rule", Description: "alpha description", RiskScore: LOW, RiskLevel: LevelLOW, MatchStrings: []string{"alpha"}},
		{ID: "bravo/two", RuleName: "bravo_rule", Description: "bravo rule", RiskScore: MEDIUM, RiskLevel: LevelMEDIUM, MatchStrings: []string{"bravo"}},
		{ID: "charlie/three", RuleName: "charlie_rule", Description: "charlie rule", RiskScore: HIGH, RiskLevel: LevelHIGH, MatchStrings: []string{"charlie"}},
	}
	got := make([]view, 0, len(fr.Behaviors))
	for _, b := range fr.Behaviors {
		got = append(got, view{
			ID:           b.ID,
			RuleName:     b.RuleName,
			Description:  b.Description,
			RiskScore:    b.RiskScore,
			RiskLevel:    b.RiskLevel,
			MatchStrings: b.MatchStrings,
		})
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("behaviors:\ngot  = %+v\nwant = %+v", got, want)
	}
	if fr.RiskScore != HIGH || fr.RiskLevel != LevelHIGH {
		t.Errorf("file risk: got = %d/%s, want = %d/%s", fr.RiskScore, fr.RiskLevel, HIGH, LevelHIGH)
	}
	if fr.Path != "test/path" || fr.SHA256 != "cksum" || fr.Size != int64(len(fc)) {
		t.Errorf("file identity: got = %q/%q/%d, want = %q/%q/%d", fr.Path, fr.SHA256, fr.Size, "test/path", "cksum", len(fc))
	}
}

func TestGenerateDropsRules(t *testing.T) {
	t.Parallel()
	// Each case places the kept rule between two dropped rules, so a dropped
	// rule is processed before the kept one regardless of match order.
	tests := []struct {
		name         string
		sources      map[string]string
		c            malcontent.Config
		kind         *programkind.FileType
		wantNames    []string
		wantMeta     map[string]string
		wantFiltered int
		wantRisk     int
	}{
		{
			name: "rules scoped to another file type are dropped",
			sources: map[string]string{
				"a/scoped": reportRuleSrc("a_scoped", "high", `filetypes = "elf"`, "aaa"),
				"b/kept":   reportRuleSrc("b_kept", "medium", "", "bbb"),
				"c/scoped": reportRuleSrc("c_scoped", "high", `filetypes = "elf"`, "ccc"),
			},
			kind:      &programkind.FileType{Ext: "py"},
			wantNames: []string{"b_kept"},
			wantRisk:  MEDIUM,
		},
		{
			name: "rules below the minimum risk are dropped",
			sources: map[string]string{
				"a/low":  reportRuleSrc("a_low", "low", "", "aaa"),
				"b/kept": reportRuleSrc("b_kept", "high", "", "bbb"),
				"c/low":  reportRuleSrc("c_low", "low", "", "ccc"),
			},
			c:         malcontent.Config{MinRisk: HIGH},
			wantNames: []string{"b_kept"},
			wantRisk:  HIGH,
		},
		{
			name: "overrides of rules that did not match are dropped",
			sources: map[string]string{
				"a/orphan": reportRuleSrc("a_orphan", "override", `missing_rule = "low"`, "aaa"),
				"b/kept":   reportRuleSrc("b_kept", "medium", "", "bbb"),
				"c/orphan": reportRuleSrc("c_orphan", "override", `missing_rule = "low"`, "ccc"),
			},
			wantNames: []string{"b_kept"},
			wantRisk:  MEDIUM,
		},
		{
			name: "meta rules populate file metadata instead of behaviors",
			sources: map[string]string{
				"a/kept":          reportRuleSrc("a_kept", "medium", "", "aaa"),
				"meta/format/one": reportRuleSrc("meta_one", "", "", "bbb"),
				"meta/kind/two":   reportRuleSrc("meta_two", "", "", "ccc"),
			},
			wantNames: []string{"a_kept"},
			wantMeta:  map[string]string{"format": "one", "kind": "two"},
			wantRisk:  MEDIUM,
		},
		{
			name: "rules with ignored tags are counted and dropped",
			sources: map[string]string{
				"a/noisy": reportRuleSrc("a_noisy", "medium noisy", "", "aaa"),
				"b/kept":  reportRuleSrc("b_kept", "medium", "", "bbb"),
				"c/noisy": reportRuleSrc("c_noisy", "medium noisy", "", "ccc"),
			},
			c:            malcontent.Config{IgnoreTags: []string{"noisy"}},
			wantNames:    []string{"b_kept"},
			wantFiltered: 2,
			wantRisk:     MEDIUM,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fr := reportGenerate(t, tt.sources, []byte("aaa bbb ccc"), "test/path", tt.c, tt.kind)
			if got := reportSortedNames(fr); !slices.Equal(got, tt.wantNames) {
				t.Errorf("behaviors: got = %v, want = %v", got, tt.wantNames)
			}
			if !maps.Equal(fr.Meta, tt.wantMeta) {
				t.Errorf("meta: got = %v, want = %v", fr.Meta, tt.wantMeta)
			}
			if fr.FilteredBehaviors != tt.wantFiltered {
				t.Errorf("FilteredBehaviors: got = %d, want = %d", fr.FilteredBehaviors, tt.wantFiltered)
			}
			if fr.RiskScore != tt.wantRisk {
				t.Errorf("RiskScore: got = %d, want = %d", fr.RiskScore, tt.wantRisk)
			}
		})
	}
}

func TestGenerateQuantityIncreasesRisk(t *testing.T) {
	t.Parallel()
	sources := map[string]string{
		"high/one": reportRuleSrc("high_one", "high", "", "aaa"),
		"high/two": reportRuleSrc("high_two", "high", "", "bbb"),
	}
	tests := []struct {
		name string
		fc   string
		qir  bool
		want int
	}{
		{"two HIGH matches in a small file upgrade to CRITICAL", "aaa bbb", true, CRITICAL},
		{"one HIGH match stays HIGH", "aaa", true, HIGH},
		{"disabled upgrade keeps HIGH", "aaa bbb", false, HIGH},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := malcontent.Config{MinRisk: LOW, QuantityIncreasesRisk: tt.qir}
			fr := reportGenerate(t, sources, []byte(tt.fc), "test/path", c, nil)
			if fr.RiskScore != tt.want || fr.RiskLevel != RiskLevels[tt.want] {
				t.Errorf("file risk: got = %d/%s, want = %d/%s", fr.RiskScore, fr.RiskLevel, tt.want, RiskLevels[tt.want])
			}
		})
	}
}

func TestGenerateIgnoreSelf(t *testing.T) {
	t.Parallel()
	const marked = `
  meta:
    __malcontent__ = "true"
  strings:
    $a = "selfmark"
  condition:
    $a
}`
	self := map[string]string{"internal/malcontent": "rule malcontent: harmless {" + marked}
	impostor := map[string]string{"other/impostor": "rule impostor: harmless {" + marked}
	unmarked := map[string]string{"internal/malcontent": `rule malcontent: harmless { strings: $a = "selfmark" condition: $a }`}

	tests := []struct {
		name           string
		sources        map[string]string
		path           string
		ignoreSelf     bool
		wantSkipped    string
		wantMalcontent bool
	}{
		{"malcontent rule on the mal binary is skipped", self, "/usr/local/bin/mal", true, "ignoring malcontent binary", true},
		{"disabled self-ignore keeps the mal binary", self, "/usr/local/bin/mal", false, "", true},
		{"malcontent rule on another binary is kept", self, "/usr/bin/ls", true, "", true},
		{"marker from a differently named rule does not skip", impostor, "/usr/local/bin/mal", true, "", true},
		{"malcontent rule without the marker does not skip", unmarked, "/usr/local/bin/mal", true, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fr := reportGenerate(t, tt.sources, []byte("selfmark"), tt.path, malcontent.Config{IgnoreSelf: tt.ignoreSelf}, nil)
			if fr.Skipped != tt.wantSkipped {
				t.Errorf("Skipped: got = %q, want = %q", fr.Skipped, tt.wantSkipped)
			}
			if fr.IsMalcontent != tt.wantMalcontent {
				t.Errorf("IsMalcontent: got = %v, want = %v", fr.IsMalcontent, tt.wantMalcontent)
			}
		})
	}
}

func TestGenerateAuthorURL(t *testing.T) {
	t.Parallel()
	sources := map[string]string{
		"auth/paren": `
rule paren_author {
  meta:
    author = "Arnim Rupp (https://github.com/ruppde)"
  strings:
    $s = "aaa"
  condition:
    $s
}`,
		"auth/explicit": `
rule explicit_author_url {
  meta:
    author     = "Jane Doe"
    author_url = "https://example.com/jane"
  strings:
    $s = "bbb"
  condition:
    $s
}`,
		"auth/forge": `
rule forge_reference {
  meta:
    reference  = "https://github.com/ruppde"
    source_url = "https://github.com/ruppde/rules/blob/main/forge.yar"
  strings:
    $s = "ccc"
  condition:
    $s
}`,
		"auth/unrelated": `
rule unrelated_reference {
  meta:
    author    = "Jane Doe (https://example.com/jane)"
    reference = "https://example.org/report"
  strings:
    $s = "ddd"
  condition:
    $s
}`,
	}
	fr := reportGenerate(t, sources, []byte("aaa bbb ccc ddd"), "test/path", malcontent.Config{MinRisk: LOW}, nil)
	byRule := make(map[string]*malcontent.Behavior, len(fr.Behaviors))
	for _, b := range fr.Behaviors {
		byRule[b.RuleName] = b
	}

	tests := []struct {
		name          string
		rule          string
		wantAuthor    string
		wantAuthorURL string
		wantReference string
	}{
		{"author URL from the author field is kept without a reference", "paren_author", "Arnim Rupp", "https://github.com/ruppde", ""},
		{"explicit author URL is kept without a reference", "explicit_author_url", "Jane Doe", "https://example.com/jane", ""},
		{"reference that prefixes the rule URL becomes the author URL", "forge_reference", "", "https://github.com/ruppde", ""},
		{"unrelated reference leaves the author URL alone", "unrelated_reference", "Jane Doe", "https://example.com/jane", "https://example.org/report"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := byRule[tt.rule]
			if b == nil {
				t.Fatalf("behavior %q missing; got %v", tt.rule, reportSortedNames(fr))
			}
			if b.RuleAuthor != tt.wantAuthor {
				t.Errorf("RuleAuthor: got = %q, want = %q", b.RuleAuthor, tt.wantAuthor)
			}
			if b.RuleAuthorURL != tt.wantAuthorURL {
				t.Errorf("RuleAuthorURL: got = %q, want = %q", b.RuleAuthorURL, tt.wantAuthorURL)
			}
			if b.ReferenceURL != tt.wantReference {
				t.Errorf("ReferenceURL: got = %q, want = %q", b.ReferenceURL, tt.wantReference)
			}
		})
	}
}

func TestGenerateScanKeepsHighWithoutQuantityRisk(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, map[string]string{
		"high/one":   reportRuleSrc("high_one", "high", "", "aaa"),
		"high/two":   reportRuleSrc("high_two", "high", "", "bbb"),
		"medium/one": reportRuleSrc("medium_one", "medium", "", "ccc"),
	})
	fc := []byte("aaa bbb ccc")
	mrs := scanBuf(t, rules, fc)

	tests := []struct {
		name     string
		qir      bool
		wantRisk int
	}{
		{"quantity upgrade disabled keeps HIGH findings at HIGH", false, HIGH},
		{"quantity upgrade enabled raises two HIGH findings to CRITICAL", true, CRITICAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := malcontent.Config{Scan: true, QuantityIncreasesRisk: tt.qir, MinRisk: LOW}
			highest := HighestMatchRisk(mrs, nil, "test/path", "", c)
			fr, err := Generate(t.Context(), "test/path", mrs, c, "", nil, fc, int64(len(fc)), "cksum", nil, highest)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if got, want := reportSortedNames(fr), []string{"high_one", "high_two"}; !slices.Equal(got, want) {
				t.Errorf("behaviors: got = %v, want = %v", got, want)
			}
			if fr.RiskScore != tt.wantRisk {
				t.Errorf("RiskScore: got = %d, want = %d", fr.RiskScore, tt.wantRisk)
			}
			if fr.Skipped != "" {
				t.Errorf("Skipped: got = %q, want = \"\"", fr.Skipped)
			}
		})
	}
}

func TestGenerateOverrideSeverities(t *testing.T) {
	t.Parallel()
	targets := map[string]string{
		"a/target": reportRuleSrc("target_a", "high", "", "aaa"),
		"b/target": reportRuleSrc("target_b", "high", "", "bbb"),
		"c/target": reportRuleSrc("target_c", "high", "", "ccc"),
	}
	override := func(name string, keys ...string) string {
		meta := ""
		for _, k := range keys {
			meta += "    " + k + "\n"
		}
		return fmt.Sprintf("rule %s: override {\n  meta:\n%s  strings:\n    $s = \"aaa\"\n  condition:\n    $s\n}\n", name, meta)
	}

	tests := []struct {
		name          string
		overrides     map[string]string
		wantRisk      map[string]int
		wantOverrides []string
		wantFileRisk  int
	}{
		{
			name:          "single key lowers only its target",
			overrides:     map[string]string{"fp/one": override("fp_one", `target_a = "low"`)},
			wantRisk:      map[string]int{"target_a": LOW, "target_b": HIGH, "target_c": HIGH},
			wantOverrides: []string{"fp_one:target_a:1"},
			wantFileRisk:  HIGH,
		},
		{
			name:          "mixed severities in one rule apply per key",
			overrides:     map[string]string{"fp/mixed": override("fp_mixed", `target_a = "medium"`, `target_b = "low"`)},
			wantRisk:      map[string]int{"target_a": MEDIUM, "target_b": LOW, "target_c": HIGH},
			wantOverrides: []string{"fp_mixed:target_a:2", "fp_mixed:target_b:1"},
			wantFileRisk:  HIGH,
		},
		{
			name: "key repeated across override rules keeps each rule's other severities",
			overrides: map[string]string{
				"fp/first":  override("fp_first", `target_a = "medium"`, `target_b = "low"`),
				"fp/second": override("fp_second", `target_a = "medium"`, `target_c = "harmless"`),
			},
			wantRisk:      map[string]int{"target_a": MEDIUM, "target_b": LOW, "target_c": HARMLESS},
			wantOverrides: []string{"fp_first:target_a:2", "fp_first:target_b:1", "fp_second:target_a:2", "fp_second:target_c:0"},
			wantFileRisk:  MEDIUM,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sources := maps.Clone(targets)
			maps.Copy(sources, tt.overrides)
			fr := reportGenerate(t, sources, []byte("aaa bbb ccc"), "test/path", malcontent.Config{MinRisk: HARMLESS}, nil)

			gotRisk := make(map[string]int, len(fr.Behaviors))
			for _, b := range fr.Behaviors {
				gotRisk[b.RuleName] = b.RiskScore
				if b.RiskLevel != RiskLevels[b.RiskScore] {
					t.Errorf("%s RiskLevel: got = %q, want = %q", b.RuleName, b.RiskLevel, RiskLevels[b.RiskScore])
				}
			}
			if !maps.Equal(gotRisk, tt.wantRisk) {
				t.Errorf("risk by rule: got = %v, want = %v", gotRisk, tt.wantRisk)
			}

			gotOverrides := make([]string, 0, len(fr.Overrides))
			for _, o := range fr.Overrides {
				gotOverrides = append(gotOverrides, fmt.Sprintf("%s:%s:%d", o.RuleName, strings.Join(o.Override, ","), o.RiskScore))
				if want := RiskLevels[o.RiskScore]; o.RiskLevel != want {
					t.Errorf("override %s RiskLevel: got = %q, want = %q", o.RuleName, o.RiskLevel, want)
				}
			}
			slices.Sort(gotOverrides)
			if !slices.Equal(gotOverrides, tt.wantOverrides) {
				t.Errorf("override entries: got = %v, want = %v", gotOverrides, tt.wantOverrides)
			}
			if fr.RiskScore != tt.wantFileRisk {
				t.Errorf("file RiskScore: got = %d, want = %d", fr.RiskScore, tt.wantFileRisk)
			}
		})
	}
}

// TestReportBuilderRenderTiming checks that add renders the match strings of
// override rules at once, so override entries carry them, and leaves every
// other behavior to finish, which renders only the behaviors that remain.
func TestReportBuilderRenderTiming(t *testing.T) {
	t.Parallel()
	yrs := compileTestRules(t, map[string]string{
		"render/target.yara": reportRuleSrc("render_target", "high", "", "TARGETMARK"),
		"render/fp.yara":     reportRuleSrc("render_fp", "override", `render_target = "medium"`, "FPMARK"),
	})
	fc := []byte("TARGETMARK FPMARK")
	matching := scanBuf(t, yrs, fc).MatchingRules()
	infos := ruleInfosFor(nil)
	rb := newReportBuilder(initFileReport("test/path", "cksum", int64(len(fc)), len(matching)), fc, matching)
	for _, m := range matching {
		rb.add(m, infos.get(m), nil)
	}

	added := make(map[string][]string, len(rb.fr.Behaviors))
	for _, b := range rb.fr.Behaviors {
		added[b.RuleName] = b.MatchStrings
	}
	if got, ok := added["render_target"]; !ok || got != nil {
		t.Errorf("render_target MatchStrings after add: got = %q (present: %v), want = nil", got, ok)
	}
	if got, want := added["render_fp"], []string{"FPMARK"}; !slices.Equal(got, want) {
		t.Errorf("render_fp MatchStrings after add: got = %q, want = %q", got, want)
	}

	fr := rb.finish(LOW, false)
	if len(fr.Behaviors) != 1 {
		t.Fatalf("behaviors after finish: got = %v, want only %q", reportSortedNames(fr), "render_target")
	}
	if b, want := fr.Behaviors[0], []string{"TARGETMARK"}; b.RuleName != "render_target" || b.RiskScore != MEDIUM || !slices.Equal(b.MatchStrings, want) {
		t.Errorf("behavior after finish: got = %s/%d/%q, want = render_target/%d/%q", b.RuleName, b.RiskScore, b.MatchStrings, MEDIUM, want)
	}
	if len(fr.Overrides) != 1 || !slices.Equal(fr.Overrides[0].MatchStrings, []string{"FPMARK"}) {
		t.Errorf("Overrides: got = %+v, want one entry with MatchStrings %q", fr.Overrides, []string{"FPMARK"})
	}
}

// TestGenerateDedupRendersStoredRule checks that when rules share a behavior
// ID, the behavior's match strings come from the rule whose behavior is kept.
// Rules in one namespace share an ID.
func TestGenerateDedupRendersStoredRule(t *testing.T) {
	t.Parallel()
	medium := reportRuleSrc("dup_medium", "medium", "", "MEDMARK")
	high := reportRuleSrc("dup_high", "high", "", "HIGHMARK")
	tests := []struct {
		name string
		src  string
	}{
		{"higher risk declared later replaces the behavior", medium + high},
		{"lower risk declared later leaves the behavior", high + medium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yrs := compileTestRules(t, map[string]string{"dup/rules.yara": tt.src})
			fc := []byte("MEDMARK HIGHMARK")
			c := malcontent.Config{MinRisk: LOW, Rules: yrs}
			fr, err := Generate(t.Context(), "test/path", scanBuf(t, yrs, fc), c, "", nil, fc, int64(len(fc)), "cksum", nil, 0)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if len(fr.Behaviors) != 1 {
				t.Fatalf("behaviors: got = %v, want only %q", reportSortedNames(fr), "dup_high")
			}
			if b, want := fr.Behaviors[0], []string{"HIGHMARK"}; b.RuleName != "dup_high" || b.RiskScore != HIGH || !slices.Equal(b.MatchStrings, want) {
				t.Errorf("behavior: got = %s/%d/%q, want = dup_high/%d/%q", b.RuleName, b.RiskScore, b.MatchStrings, HIGH, want)
			}
		})
	}
}

func TestGenerateScanMarksLowRiskFileSkipped(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, map[string]string{
		"medium/one": reportRuleSrc("medium_one", "medium", "", "aaa"),
	})
	fc := []byte("aaa")
	mrs := scanBuf(t, rules, fc)

	tests := []struct {
		name        string
		c           malcontent.Config
		wantSkipped string
		wantRisk    int
		wantNames   []string
	}{
		{"scan skips a file below HIGH", malcontent.Config{Scan: true, MinRisk: LOW}, "overall risk too low for scan", 0, []string{}},
		{"analyze keeps a file below HIGH", malcontent.Config{MinRisk: LOW}, "", MEDIUM, []string{"medium_one"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			highest := HighestMatchRisk(mrs, nil, "test/path", "", tt.c)
			fr, err := Generate(t.Context(), "test/path", mrs, tt.c, "", nil, fc, int64(len(fc)), "cksum", nil, highest)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if fr.Skipped != tt.wantSkipped {
				t.Errorf("Skipped: got = %q, want = %q", fr.Skipped, tt.wantSkipped)
			}
			if fr.RiskScore != tt.wantRisk || fr.RiskLevel != RiskLevels[tt.wantRisk] {
				t.Errorf("file risk: got = %d/%s, want = %d/%s", fr.RiskScore, fr.RiskLevel, tt.wantRisk, RiskLevels[tt.wantRisk])
			}
			if got := reportSortedNames(fr); !slices.Equal(got, tt.wantNames) {
				t.Errorf("behaviors: got = %v, want = %v", got, tt.wantNames)
			}
		})
	}
}

func TestGenerateRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, map[string]string{"a/one": reportRuleSrc("one", "high", "", "aaa")})
	fc := []byte("aaa")
	mrs := scanBuf(t, rules, fc)
	c := malcontent.Config{MinRisk: LOW}

	t.Run("canceled context yields an empty report", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		fr, err := Generate(ctx, "test/path", mrs, c, "", nil, fc, int64(len(fc)), "cksum", nil, 0)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error: got = %v, want = %v", err, context.Canceled)
		}
		if fr == nil || !reflect.DeepEqual(*fr, malcontent.FileReport{}) {
			t.Errorf("report: got = %+v, want an empty report", fr)
		}
	})

	t.Run("missing scan results yield no report", func(t *testing.T) {
		t.Parallel()
		fr, err := Generate(t.Context(), "test/path", nil, c, "", nil, fc, int64(len(fc)), "cksum", nil, 0)
		if err == nil {
			t.Error("error: got = nil, want an error")
		}
		if fr != nil {
			t.Errorf("report: got = %+v, want = nil", fr)
		}
	})
}
