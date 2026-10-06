// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"reflect"
	"slices"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestContainsFoldASCII(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		haystack string
		needle   string
		want     bool
	}{
		{"empty needle matches non-empty haystack", "abc", "", true},
		{"empty needle matches empty haystack", "", "", true},
		{"needle longer than haystack does not match", "gen", "generic", false},
		{"equal length uppercase haystack matches", "GENERIC", "generic", true},
		{"equal length different text does not match", "GENERIX", "generic", false},
		{"needle at start of longer haystack matches", "Generic_Loader", "generic", true},
		{"needle at end of haystack matches", "loader_GENERIC", "generic", true},
		{"mixed case needle in middle matches", "xxKeyWordxx", "keyword", true},
		{"lowercase haystack matches", "generic", "generic", true},
		{"partial prefix before full match", "genergeneric", "generic", true},
		{"absent needle does not match", "specific_rule", "generic", false},
		{"A folds to a", "A", "a", true},
		{"Z folds to z", "Z", "z", true},
		{"at sign does not fold to backtick", "@", "`", false},
		{"left bracket does not fold to left brace", "[", "{", false},
		{"digits compare exactly", "Rule2024", "2024", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := containsFoldASCII(tt.haystack, tt.needle); got != tt.want {
				t.Errorf("containsFoldASCII(%q, %q): got = %v, want = %v", tt.haystack, tt.needle, got, tt.want)
			}
		})
	}
}

func TestBehaviorRiskExact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ns   string
		rule string
		tags []string
		want int
	}{
		{"first-party namespace defaults to LOW", "fs/file/delete.yara", "file_delete", nil, LOW},
		{"combo namespace is MEDIUM", "combo/stealer/creds.yara", "creds", nil, MEDIUM},
		{"unknown tag keeps the default", "fs/file/delete.yara", "file_delete", []string{"override"}, LOW},
		{"first known tag wins", "fs/file/delete.yara", "file_delete", []string{"override", "high", "low"}, HIGH},
		{"tag beats third-party reputation", "yara/JPCERT/rules.yar", "Lazarus_str", []string{"low"}, LOW},
		{"third-party vendor defaults to HIGH", "yara/somevendor/rules.yar", "Some_Rule", nil, HIGH},
		{"reputable vendor is CRITICAL", "yara/JPCERT/rules.yar", "Lazarus_str", nil, CRITICAL},
		{"reputable vendor with generic rule name is HIGH", "yara/JPCERT/rules.yar", "Generic_Loader", nil, HIGH},
		{"reputable vendor with generic namespace is HIGH", "yara/elastic/generic_rules.yar", "Specific_Rule", nil, HIGH},
		{"keyword in rule name is MEDIUM", "yara/somevendor/rules.yar", "KeyWord_match", nil, MEDIUM},
		{"keyword in namespace is MEDIUM", "yara/YARAForge/keyword_rules.yar", "Tool_X", nil, MEDIUM},
		{"keyword outranks reputable vendor", "yara/elastic/rules.yar", "keyword_tool", nil, MEDIUM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := behaviorRisk(tt.ns, tt.rule, tt.tags); got != tt.want {
				t.Errorf("behaviorRisk(%q, %q, %v): got = %d, want = %d", tt.ns, tt.rule, tt.tags, got, tt.want)
			}
		})
	}
}

func TestThirdPartyKeyFallbackWord(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		rule string
		want string
	}{
		{"all words filtered keeps first word that is not the source", "yara/elastic/rules.yar", "Elastic_Generic_Malware", "3P/elastic/generic"},
		{"fallback skips empty words", "yara/vendor/rules.yar", "_Generic_", "3P/vendor/generic"},
		{"fallback skips source name and trailing date", "yara/vendor/rules.yar", "Vendor_jan12", "3P/vendor"},
		{"severity-driven source keeps every word", "yara/guarddog/rules.yar", "threat_runtime_obfuscation_chr", "3P/guarddog/threat_runtime_obfuscation_chr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := thirdPartyKey(tt.path, tt.rule); got != tt.want {
				t.Errorf("thirdPartyKey(%q, %q): got = %q, want = %q", tt.path, tt.rule, got, tt.want)
			}
		})
	}
}

func TestThirdPartyKeyNamespaceShape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		rule string
		want string
	}{
		{"file directly under yara has no source and no key", "yara/rules.yar", "Some_Rule", ""},
		{"empty source directory has no key", "yara//rules.yar", "Some_Rule", ""},
		{"source directory named like a rule file has no key", "yara/old.yara/rules.yar", "Some_Rule", ""},
		{"empty word between words is skipped", "yara/vendor/rules.yar", "Alpha__Beta", "3P/vendor/alpha_beta"},
		{"three kept words stay whole", "yara/vendor/rules.yar", "Alpha_Beta_Gamma", "3P/vendor/alpha_beta_gamma"},
		{"four kept words are cut to three", "yara/vendor/rules.yar", "Alpha_Beta_Gamma_Delta", "3P/vendor/alpha_beta_gamma"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := thirdPartyKey(tt.path, tt.rule); got != tt.want {
				t.Errorf("thirdPartyKey(%q, %q): got = %q, want = %q", tt.path, tt.rule, got, tt.want)
			}
		})
	}
}

// TestThirdPartyKeySuffixes uses rule names vendored under third_party/yara.
func TestThirdPartyKeySuffixes(t *testing.T) {
	t.Parallel()
	const forge = "yara/YARAForge/yara-rules-full.yar"
	tests := []struct {
		name string
		path string
		rule string
		want string
	}{
		{"word with letters then digits is kept", "yara/guarddog/threat-runtime-obfuscation-base64exec.yar", "threat_runtime_obfuscation_base64exec", "3P/guarddog/threat_runtime_obfuscation_base64exec"},
		{"generation suffix is kept", forge, "SIGNATURE_BASE_Emdivi_Gen1", "3P/YARAForge/signature_emdivi_gen1"},
		{"sibling generation suffix gets its own key", forge, "SIGNATURE_BASE_Emdivi_Gen2", "3P/YARAForge/signature_emdivi_gen2"},
		{"generation suffix no longer collides with a dated sibling", forge, "SIGNATURE_BASE_Turla_APT_Malware_Gen1", "3P/YARAForge/signature_turla_gen1"},
		{"month and two-digit year is stripped", forge, "SIGNATURE_BASE_Waterbear_1_Jun17", "3P/YARAForge/signature_waterbear"},
		{"month and four-digit year is stripped", "yara/InQuest-VT/Apt29_DLL_May2022.yar", "apt29_dll_may2022", "3P/InQuest-VT/apt29_dll"},
		{"full month name and year is stripped", "yara/bartblaze/crimeware/ArechClient_Campaign_July2021.yar", "ArechClient_Campaign_July2021", "3P/bartblaze/arechclient_campaign"},
		{"year and month after a hex key is stripped", forge, "SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr202004_1", "3P/YARAForge/signature_turla"},
		{"long hash suffix is stripped", forge, "SIGNATURE_BASE_Webshell_E8Eaf8Da94012E866E51547Cd63Bb996379690Bf", "3P/YARAForge/signature_webshell"},
		{"long hash suffix without letter runs is stripped", forge, "SIGNATURE_BASE_Webshell_5786D7D9F4B0Df731D79Ed927Fb5A124195Fc901", "3P/YARAForge/signature_webshell"},
		{"certificate serial suffix is stripped", forge, "DITEKSHEN_INDICATOR_KB_CERT_00801689896Ed339237464A41A2900A969", "3P/YARAForge/ditekshen_kb_cert"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := thirdPartyKey(tt.path, tt.rule); got != tt.want {
				t.Errorf("thirdPartyKey(%q, %q): got = %q, want = %q", tt.path, tt.rule, got, tt.want)
			}
		})
	}
}

func TestDateWord(t *testing.T) {
	t.Parallel()
	tests := []struct {
		word string
		want bool
	}{
		{"jan01", true},
		{"nov1", true},
		{"jun17", true},
		{"may2022", true},
		{"apr202004", true},
		{"april17", true},
		{"july2021", true},
		{"sept23", true},
		{"base64exec", false},
		{"base64", false},
		{"gen2", false},
		{"utf16", false},
		{"decoder2", false},
		{"jun123", false},
		{"xjun17", false},
		{"jun17x", false},
		{"jun", false},
	}
	for _, tt := range tests {
		t.Run(tt.word, func(t *testing.T) {
			t.Parallel()
			if got := dateRe.MatchString(tt.word); got != tt.want {
				t.Errorf("dateRe.MatchString(%q): got = %v, want = %v", tt.word, got, tt.want)
			}
		})
	}
}

func TestIsHexWord(t *testing.T) {
	t.Parallel()
	tests := []struct {
		word string
		want bool
	}{
		{"e4a1982b", true},
		{"0", true},
		{"5786d7d9f4b0df731d79ed927fb5a124195fc901", true},
		{"", false},
		{"e4a1982g", false},
		{"E4A1982B", false},
		{"gen2", false},
	}
	for _, tt := range tests {
		t.Run(tt.word, func(t *testing.T) {
			t.Parallel()
			if got := isHexWord(tt.word); got != tt.want {
				t.Errorf("isHexWord(%q): got = %v, want = %v", tt.word, got, tt.want)
			}
		})
	}
}

func TestGenerateKeySingleSegment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"single segment keeps underscores", "foo_bar.yara", "foo_bar"},
		{"single segment dash becomes underscore", "anti-static.yara", "anti_static"},
		{"namespace segment keeps its dash", "anti-static/elf.yara", "anti-static/elf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := generateKey(tt.src, "rule_name"); got != tt.want {
				t.Errorf("generateKey(%q): got = %q, want = %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestLongestUniqueContainment(t *testing.T) {
	t.Parallel()

	// With every byte value present, findSeparator falls back to 0, so the
	// separator also occurs inside keys. "\x00c" then appears in the combined
	// buffer starting on the separator after wide, but it is not a substring
	// of wide and must be kept. Adding "\x00a" moves "\x00c" off the first
	// sorted position, so a separator match cannot be mistaken for a match
	// inside "\x00c" itself.
	all := make([]byte, 0, 256)
	all = append(all, 'b')
	for c := 1; c < 256; c++ {
		all = append(all, byte(c))
	}
	wide := string(all)

	tests := []struct {
		name string
		raw  []string
		want []string
	}{
		{"substring of the first sorted key is dropped", []string{"b", "ab"}, []string{"ab"}},
		{"unrelated keys are kept longest first", []string{"zz", "z", "ab"}, []string{"ab", "zz"}},
		{"match starting on a separator byte is not containment", []string{"c", wide, "\x00c"}, []string{wide, "\x00c"}},
		{"separator match for a key after the first is not containment", []string{"c", wide, "\x00c", "\x00a"}, []string{wide, "\x00a", "\x00c"}},
		{"only empty strings yield nil", []string{"", ""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := longestUnique(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("longestUnique(%q): got = %q, want = %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestMatchStrings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ruleName string
		ms       []string
		want     []string
	}{
		{"nil input yields nil", "rule", nil, nil},
		{"blank matches are dropped", "rule", []string{"  ", "", "abc"}, []string{"abc"}},
		{"substrings collapse into the longest match", "rule", []string{" curl ", "curl -k", "curl"}, []string{"curl -k"}},
		{"base64 rule names prefix each match", "base64_payload", []string{"aGk="}, []string{"base64_payload::aGk="}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchStrings(tt.ruleName, tt.ms); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("matchStrings(%q, %q): got = %q, want = %q", tt.ruleName, tt.ms, got, tt.want)
			}
		})
	}
}

func TestPathMatchesGlobsSkipsEmptyEntries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		patterns string
		path     string
		want     bool
	}{
		{"empty entry between patterns is skipped", "*.go,,*.py", "pkg/mod.py", true},
		{"leading empty entry is skipped", ",*.py", "mod.py", true},
		{"whitespace-only entry is skipped", "*.go, ,*.py", "mod.py", true},
		{"only empty entries never match", ",,", "mod.py", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pathMatchesGlobs(tt.patterns, tt.path); got != tt.want {
				t.Errorf("pathMatchesGlobs(%q, %q): got = %v, want = %v", tt.patterns, tt.path, got, tt.want)
			}
		})
	}
}

func TestPathMatchesGlobsLiteralCharacters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		patterns string
		path     string
		want     bool
	}{
		{"dot matches only a dot", "*.py", "pkg/mod_py", false},
		{"plus matches only a plus", "a+b.txt", "dir/aab.txt", false},
		{"brackets match only brackets", "[ab].js", "dir/a.js", false},
		{"pattern with regexp metacharacters matches itself", "[ab]+c.txt", "dir/[ab]+c.txt", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pathMatchesGlobs(tt.patterns, tt.path); got != tt.want {
				t.Errorf("pathMatchesGlobs(%q, %q): got = %v, want = %v", tt.patterns, tt.path, got, tt.want)
			}
		})
	}
}

func TestCompileGlobReusesCompiledPattern(t *testing.T) {
	t.Parallel()
	const pattern = "*.report-logic-test-glob"
	first := compileGlob(pattern)
	if second := compileGlob(pattern); second != first {
		t.Errorf("second compileGlob(%q): got = %p, want = %p (the cached regexp)", pattern, second, first)
	}
}

func TestUpgradeRiskMiBBoundaries(t *testing.T) {
	t.Parallel()
	const mib int64 = 1024 * 1024
	tests := []struct {
		name      string
		size      int64
		highCount int
		want      bool
	}{
		{"just under 2 MiB upgrades with 3 highs", 2*mib - 1, 3, true},
		{"just under 2 MiB stays with 2 highs", 2*mib - 1, 2, false},
		{"exactly 2 MiB stays with 3 highs", 2 * mib, 3, false},
		{"exactly 2 MiB upgrades with 4 highs", 2 * mib, 4, true},
		{"3 MiB stays with 3 highs", 3 * mib, 3, false},
		{"just under 4 MiB upgrades with 4 highs", 4*mib - 1, 4, true},
		{"exactly 4 MiB stays with 4 highs", 4 * mib, 4, false},
		{"exactly 4 MiB upgrades with 5 highs", 4 * mib, 5, true},
		{"just under 10 MiB upgrades with 5 highs", 10*mib - 1, 5, true},
		{"exactly 10 MiB stays with 5 highs", 10 * mib, 5, false},
		{"exactly 10 MiB upgrades with 6 highs", 10 * mib, 6, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := upgradeRisk(t.Context(), HIGH, map[int]int{HIGH: tt.highCount}, tt.size); got != tt.want {
				t.Errorf("upgradeRisk(HIGH, %d highs, %d bytes): got = %v, want = %v", tt.highCount, tt.size, got, tt.want)
			}
		})
	}
}

func TestSkipMatchThresholds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		ignoreMalcontent bool
		override         bool
		scan             bool
		risk             int
		threshold        int
		highestRisk      int
		want             bool
	}{
		{name: "invalid risk is dropped even for overrides", override: true, risk: INVALID, want: true},
		{name: "analyze keeps a match at the threshold", risk: MEDIUM, threshold: MEDIUM},
		{name: "analyze drops a match below the threshold", risk: LOW, threshold: MEDIUM, want: true},
		{name: "analyze keeps a below-threshold match when malcontent is ignored", ignoreMalcontent: true, risk: LOW, threshold: MEDIUM},
		{name: "analyze keeps a below-threshold override", override: true, risk: LOW, threshold: MEDIUM},
		{name: "analyze ignores the highest risk", risk: MEDIUM, threshold: LOW, highestRisk: HIGH},
		{name: "scan keeps a match at the highest risk", scan: true, risk: HIGH, highestRisk: HIGH},
		{name: "scan drops a match below the highest risk", scan: true, risk: MEDIUM, highestRisk: HIGH, want: true},
		{name: "scan ignores the analyze threshold", scan: true, risk: HIGH, threshold: CRITICAL, highestRisk: HIGH},
		{name: "scan keeps a below-highest match when malcontent is ignored", ignoreMalcontent: true, scan: true, risk: MEDIUM, highestRisk: HIGH},
		{name: "scan keeps a below-highest override", override: true, scan: true, risk: MEDIUM, highestRisk: HIGH},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := skipMatch(tt.ignoreMalcontent, tt.override, tt.scan, tt.risk, tt.threshold, tt.highestRisk); got != tt.want {
				t.Errorf("skipMatch(ignore=%v, override=%v, scan=%v, risk=%d, threshold=%d, highest=%d): got = %v, want = %v",
					tt.ignoreMalcontent, tt.override, tt.scan, tt.risk, tt.threshold, tt.highestRisk, got, tt.want)
			}
		})
	}
}

func TestUpdateBehaviorTies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		existing malcontent.Behavior
		incoming malcontent.Behavior
		wantRule string
		wantDesc string
		wantRisk int
	}{
		{
			name:     "equal risk keeps the existing entry",
			existing: malcontent.Behavior{ID: "k", RuleName: "first", RiskScore: MEDIUM, Description: "a long description"},
			incoming: malcontent.Behavior{ID: "k", RuleName: "second", RiskScore: MEDIUM, Description: "short"},
			wantRule: "first",
			wantDesc: "a long description",
			wantRisk: MEDIUM,
		},
		{
			name:     "equal risk and equal-length description keeps existing text",
			existing: malcontent.Behavior{ID: "k", RuleName: "first", RiskScore: MEDIUM, Description: "aaaa"},
			incoming: malcontent.Behavior{ID: "k", RuleName: "second", RiskScore: MEDIUM, Description: "bbbb"},
			wantRule: "first",
			wantDesc: "aaaa",
			wantRisk: MEDIUM,
		},
		{
			name:     "equal risk adopts a longer description",
			existing: malcontent.Behavior{ID: "k", RuleName: "first", RiskScore: MEDIUM, Description: "short"},
			incoming: malcontent.Behavior{ID: "k", RuleName: "second", RiskScore: MEDIUM, Description: "much longer"},
			wantRule: "first",
			wantDesc: "much longer",
			wantRisk: MEDIUM,
		},
		{
			name:     "lower risk does not lend its longer description",
			existing: malcontent.Behavior{ID: "k", RuleName: "first", RiskScore: HIGH, Description: "short"},
			incoming: malcontent.Behavior{ID: "k", RuleName: "second", RiskScore: LOW, Description: "a much longer description"},
			wantRule: "first",
			wantDesc: "short",
			wantRisk: HIGH,
		},
		{
			name:     "higher risk replaces the entry",
			existing: malcontent.Behavior{ID: "k", RuleName: "first", RiskScore: LOW, Description: "a long description"},
			incoming: malcontent.Behavior{ID: "k", RuleName: "second", RiskScore: HIGH, Description: "short"},
			wantRule: "second",
			wantDesc: "short",
			wantRisk: HIGH,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			existing, incoming := tt.existing, tt.incoming
			fr := &malcontent.FileReport{Behaviors: []*malcontent.Behavior{&existing}}
			updateBehavior(fr, &incoming, "k", nil)
			if len(fr.Behaviors) != 1 {
				t.Fatalf("behaviors: got = %d, want = 1", len(fr.Behaviors))
			}
			got := fr.Behaviors[0]
			if got.RuleName != tt.wantRule {
				t.Errorf("RuleName: got = %q, want = %q", got.RuleName, tt.wantRule)
			}
			if got.Description != tt.wantDesc {
				t.Errorf("Description: got = %q, want = %q", got.Description, tt.wantDesc)
			}
			if got.RiskScore != tt.wantRisk {
				t.Errorf("RiskScore: got = %d, want = %d", got.RiskScore, tt.wantRisk)
			}
		})
	}
}

func TestHandleOverridesThresholds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scan     bool
		minScore int
		want     []string
	}{
		{"analyze keeps behaviors at or above minScore", false, MEDIUM, []string{"critical_rule", "high_rule", "medium_rule"}},
		{"analyze drops behaviors below minScore", false, CRITICAL, []string{"critical_rule"}},
		{"scan keeps HIGH and above under a low minScore", true, LOW, []string{"critical_rule", "high_rule"}},
		{"scan keeps HIGH and above under a CRITICAL minScore", true, CRITICAL, []string{"critical_rule", "high_rule"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			original := []*malcontent.Behavior{
				{ID: "a", RuleName: "medium_rule", RiskScore: MEDIUM, RiskLevel: LevelMEDIUM},
				{ID: "b", RuleName: "high_rule", RiskScore: HIGH, RiskLevel: LevelHIGH},
				{ID: "c", RuleName: "critical_rule", RiskScore: CRITICAL, RiskLevel: LevelCRITICAL},
			}
			var got []string
			for _, b := range handleOverrides(original, nil, tt.minScore, tt.scan) {
				got = append(got, b.RuleName)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("kept rules: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestHandleOverridesPerTargetSeverity(t *testing.T) {
	t.Parallel()
	entry := func(rule, target string, score int) *malcontent.Behavior {
		return &malcontent.Behavior{RuleName: rule, RiskScore: score, RiskLevel: RiskLevels[score], Override: []string{target}}
	}
	tests := []struct {
		name      string
		overrides []*malcontent.Behavior
		want      map[string]int
	}{
		{
			name:      "single target is set to its severity",
			overrides: []*malcontent.Behavior{entry("fp", "a", LOW)},
			want:      map[string]int{"a": LOW, "b": HIGH, "c": HIGH},
		},
		{
			name:      "entries from one rule keep separate severities",
			overrides: []*malcontent.Behavior{entry("fp", "a", MEDIUM), entry("fp", "b", LOW)},
			want:      map[string]int{"a": MEDIUM, "b": LOW, "c": HIGH},
		},
		{
			name:      "later entry for a repeated target wins",
			overrides: []*malcontent.Behavior{entry("fp1", "a", MEDIUM), entry("fp1", "b", LOW), entry("fp2", "a", HARMLESS)},
			want:      map[string]int{"a": HARMLESS, "b": LOW, "c": HIGH},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			original := []*malcontent.Behavior{
				{ID: "a", RuleName: "a", RiskScore: HIGH, RiskLevel: LevelHIGH},
				{ID: "b", RuleName: "b", RiskScore: HIGH, RiskLevel: LevelHIGH},
				{ID: "c", RuleName: "c", RiskScore: HIGH, RiskLevel: LevelHIGH},
			}
			got := map[string]int{}
			for _, b := range handleOverrides(original, tt.overrides, HARMLESS, false) {
				got[b.RuleName] = b.RiskScore
				if b.RiskLevel != RiskLevels[b.RiskScore] {
					t.Errorf("%s RiskLevel: got = %q, want = %q", b.RuleName, b.RiskLevel, RiskLevels[b.RiskScore])
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("risk by rule: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestOverrideEntries(t *testing.T) {
	t.Parallel()
	rule := &malcontent.Behavior{
		ID:          "false-positives/vendor",
		RuleName:    "vendor_fp",
		Description: "vendor tool",
		RiskScore:   LOW,
		RiskLevel:   LevelLOW,
		Override:    []string{"a", "b"},
	}
	got := overrideEntries([]overrideTarget{
		{rule: rule, target: "a", score: MEDIUM},
		{rule: rule, target: "b", score: LOW},
	})
	want := []*malcontent.Behavior{
		{ID: "false-positives/vendor", RuleName: "vendor_fp", Description: "vendor tool", RiskScore: MEDIUM, RiskLevel: LevelMEDIUM, Override: []string{"a"}},
		{ID: "false-positives/vendor", RuleName: "vendor_fp", Description: "vendor tool", RiskScore: LOW, RiskLevel: LevelLOW, Override: []string{"b"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("overrideEntries:\ngot  = %+v\nwant = %+v", got, want)
	}
	if !reflect.DeepEqual(rule.Override, []string{"a", "b"}) || rule.RiskScore != LOW {
		t.Errorf("source behavior modified: got = %+v", *rule)
	}
}

func TestTrimDisplayPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		path   string
		expath string
		c      malcontent.Config
		want   string
	}{
		{"no options leave the path unchanged", "/tmp/x/bin/ls", "/tmp/x", malcontent.Config{}, "/tmp/x/bin/ls"},
		{"OCI strips the extraction root", "/tmp/x/bin/ls", "/tmp/x", malcontent.Config{OCI: true}, "/bin/ls"},
		{"trim prefixes are applied", "/samples/a/b", "", malcontent.Config{TrimPrefixes: []string{"/samples"}}, "a/b"},
		{"OCI root is stripped before trim prefixes", "/tmp/x/samples/a", "/tmp/x", malcontent.Config{OCI: true, TrimPrefixes: []string{"/samples"}}, "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := trimDisplayPath(tt.path, tt.expath, tt.c); got != tt.want {
				t.Errorf("trimDisplayPath(%q, %q): got = %q, want = %q", tt.path, tt.expath, got, tt.want)
			}
		})
	}
}
