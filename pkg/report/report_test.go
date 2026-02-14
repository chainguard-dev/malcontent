// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestLongestUnique(t *testing.T) {
	tests := []struct {
		name string
		raw  []string
		want []string
	}{
		{
			name: "Test 1",
			raw:  []string{"apple", "banana", "cherry", "applecherry", "bananaapple", "cherrybanana"},
			want: []string{"cherrybanana", "applecherry", "bananaapple"},
		},
		{
			name: "Test 2",
			raw:  []string{"test", "testing", "tester", "testest"},
			want: []string{"testest", "testing", "tester"},
		},
		{
			name: "Test 3",
			raw:  []string{"", "a", "aa", "aaa"},
			want: []string{"aaa"},
		},
		{
			name: "Test 4",
			raw:  []string{"abc", "def", "ghi"},
			want: []string{"abc", "def", "ghi"},
		},
		{
			name: "Test 5",
			raw:  []string{"abc", "abcabc", "abcabcabc"},
			want: []string{"abcabcabc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := longestUnique(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("longestUnique() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkLongestUnique(b *testing.B) {
	raw := []string{
		"_proc_download_content",
		"apple",
		"applecherry",
		"banana",
		"bananaapple",
		"cherry",
		"cherrybanana",
		"upload_content",
	}
	for b.Loop() {
		longestUnique(raw)
	}
}

func TestUpgradeRisk(t *testing.T) {
	tests := []struct {
		name         string
		currentScore int
		riskCounts   map[int]int
		size         int64
		want         bool
	}{
		{"no risk", 0, map[int]int{}, 1024, false},
		{"tiny-risky", 3, map[int]int{3: 2}, 310, true},
		{"small-not", 3, map[int]int{3: 2}, 8192, false},
		{"small-risky", 3, map[int]int{3: 3}, 8192, true},
		{"large-not", 3, map[int]int{3: 3}, 1024 * 1024 * 1024, false},
		{"large-yes", 3, map[int]int{3: 10}, 1024 * 1024 * 1024, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := upgradeRisk(context.Background(), tt.currentScore, tt.riskCounts, tt.size); got != tt.want {
				t.Errorf("upgradeRisk(%d, %v, %v) = %v, want %v", tt.currentScore, tt.riskCounts, tt.size, got, tt.want)
			}
		})
	}
}

func TestSkipMatch(t *testing.T) {
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
		{
			name:             "unmodified risk edge case",
			ignoreMalcontent: false,
			override:         false,
			scan:             false,
			risk:             -1,
			threshold:        1,
			highestRisk:      1,
			want:             true,
		},
		{
			name:             "ordinary analyze",
			ignoreMalcontent: false,
			override:         false,
			scan:             false,
			risk:             2,
			threshold:        1,
			highestRisk:      1,
			want:             false,
		},
		{
			name:             "ordinary scan with HIGH threshold",
			ignoreMalcontent: false,
			override:         false,
			scan:             true,
			risk:             2,
			threshold:        3,
			highestRisk:      3,
			want:             true,
		},
		{
			name:             "ordinary scan with HIGH risk and HIGH threshold",
			ignoreMalcontent: false,
			override:         false,
			scan:             true,
			risk:             3,
			threshold:        3,
			highestRisk:      3,
			want:             false,
		},
		{
			name:             "ordinary scan with HIGH risk and CRITICAL threshold",
			ignoreMalcontent: false,
			override:         false,
			scan:             true,
			risk:             3,
			threshold:        4,
			highestRisk:      4,
			want:             true,
		},
		{
			name:             "ordinary scan with CRITICAL risk and CRITICAL threshold",
			ignoreMalcontent: false,
			override:         false,
			scan:             true,
			risk:             4,
			threshold:        4,
			highestRisk:      4,
			want:             false,
		},
		{
			name:             "ordinary analyze with override to downgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             false,
			risk:             2,
			threshold:        1,
			highestRisk:      4,
			want:             false,
		},
		{
			name:             "analyze with override to upgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             true,
			risk:             4,
			threshold:        1,
			highestRisk:      2,
			want:             false,
		},
		{
			name:             "scan with override to upgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             true,
			risk:             4,
			threshold:        3,
			highestRisk:      3,
			want:             false,
		},
		{
			name:             "scan with override to downgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             true,
			risk:             2,
			threshold:        3,
			highestRisk:      3,
			want:             false,
		},
		{
			name:             "scan with override to upgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             true,
			risk:             4,
			threshold:        3,
			highestRisk:      3,
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := skipMatch(tt.ignoreMalcontent, tt.override, tt.scan, tt.risk, tt.threshold, tt.highestRisk); got != tt.want {
				t.Errorf("skipMatch(%v, %v, %v, %d, %d, %d) = %v, want %v", tt.ignoreMalcontent, tt.override, tt.scan, tt.risk, tt.threshold, tt.highestRisk, got, tt.want)
			}
		})
	}
}

func TestSkipScanFile(t *testing.T) {
	tests := []struct {
		name             string
		scan             bool
		overallRiskScore int
		want             bool
	}{
		{
			name:             "analyze with non-HIGH",
			scan:             false,
			overallRiskScore: 2,
			want:             false,
		},
		{
			name:             "analyze with HIGH",
			scan:             false,
			overallRiskScore: 3,
			want:             false,
		},
		{
			name:             "analyze with CRITICAL",
			scan:             false,
			overallRiskScore: 3,
			want:             false,
		},
		{
			name:             "scan with non-HIGH",
			scan:             true,
			overallRiskScore: 2,
			want:             true,
		},
		{
			name:             "scan with HIGH",
			scan:             true,
			overallRiskScore: 3,
			want:             false,
		},
		{
			name:             "scan with CRITICAL",
			scan:             true,
			overallRiskScore: 3,
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := skipScanFile(tt.scan, tt.overallRiskScore); got != tt.want {
				t.Errorf("skipScanFile(%v, %d) = %v, want %v", tt.scan, tt.overallRiskScore, got, tt.want)
			}
		})
	}
}

func TestApplyCriticalUpgrade(t *testing.T) {
	tests := []struct {
		name                  string
		quantityIncreasesRisk bool
		riskCounts            map[int]int
		overallRiskScore      int
		size                  int64
		want                  bool
	}{
		{
			name:                  "several highs but no increase",
			quantityIncreasesRisk: false,
			riskCounts: map[int]int{
				3: 100,
			},
			overallRiskScore: 3,
			size:             1000,
			want:             false,
		},
		{
			name:                  "several highs with increase",
			quantityIncreasesRisk: true,
			riskCounts: map[int]int{
				3: 10,
			},
			overallRiskScore: 3,
			size:             1000,
			want:             true,
		},
		{
			name:                  "no highs with increase",
			quantityIncreasesRisk: true,
			riskCounts: map[int]int{
				0: 1,
				1: 5,
				2: 100,
			},
			overallRiskScore: 2,
			size:             1000,
			want:             false,
		},
		{
			name:                  "no highs with no increase",
			quantityIncreasesRisk: false,
			riskCounts: map[int]int{
				0: 1,
				1: 1,
				2: 1,
			},
			overallRiskScore: 2,
			size:             1000,
			want:             false,
		},
		{
			name:                  "highs and criticals with no increase",
			quantityIncreasesRisk: false,
			riskCounts: map[int]int{
				3: 4,
				4: 1,
			},
			overallRiskScore: 4,
			size:             1000,
			want:             false,
		},
		{
			name:                  "highs and criticals with increase and already critical",
			quantityIncreasesRisk: true,
			riskCounts: map[int]int{
				3: 3,
				4: 1,
			},
			overallRiskScore: 4, // only 3 is a valid risk score for upgradeRisk
			size:             1.5 * 1024 * 1024,
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := applyCriticalUpgrade(context.Background(), tt.quantityIncreasesRisk, tt.riskCounts, tt.overallRiskScore, tt.size); got != tt.want {
				t.Errorf("applyCriticalUpgrade(ctx, %v, %v, %d, %d) = %v, want %v", tt.quantityIncreasesRisk, tt.riskCounts, tt.overallRiskScore, tt.size, got, tt.want)
			}
		})
	}
}

func TestIsMalcontent(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"unrelated file", "/usr/bin/foo", false},
		{"make out/mal", "out/mal", true},
		{"installed binary", "/usr/local/bin/mal", true},
		{"NAME", "malcontent", true},
		{"NAME uppercase", "MALCONTENT", true},
		{"installation to opt with NAME", "opt/malcontent", true},
		{"binary name uppercase", "out/MAL", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isMalcontent(tt.path); got != tt.want {
				t.Errorf("isMalcontent(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestThirdPartyKey(t *testing.T) {
	tests := []struct {
		name string
		path string
		rule string
		want string
	}{
		{
			name: "ELASTIC Linux Trojan",
			path: "yara/elastic/linux_trojan_gafgyt.yara",
			rule: "ELASTIC_Linux_Trojan_Gafgyt_E4A1982B",
			want: "3P/elastic/gafgyt",
		},
		{
			name: "no yara path",
			path: "rules/malware/trojan.yara",
			rule: "trojan_test",
			want: "",
		},
		{
			name: "with hex suffix",
			path: "yara/signature/test.yara",
			rule: "SIG_Test_Rule_ABC123",
			want: "3P/sig_base/rule",
		},
		{
			name: "with date suffix",
			path: "yara/malware/test.yara",
			rule: "Malware_Test_jan01",
			want: "3P/malware/test",
		},
		{
			name: "many junk words",
			path: "yara/forensic/test.yara",
			rule: "forensic_generic_malware_trojan_suspicious_test_hunting",
			want: "3P/forensic/test",
		},
		{
			name: "max 4 words",
			path: "yara/source/test.yara",
			rule: "Test_Word1_Word2_Word3_Word4_Word5_Word6",
			want: "3P/source/word1_word2_word3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := thirdPartyKey(tt.path, tt.rule)
			if got != tt.want {
				t.Errorf("thirdPartyKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		rule string
		want string
	}{
		{
			name: "third party rule",
			src:  "yara/elastic/test.yara",
			rule: "ELASTIC_Test_Rule",
			want: "3P/elastic/rule",
		},
		{
			name: "simple rule",
			src:  "malware/trojan.yara",
			rule: "trojan_test",
			want: "malware/trojan",
		},
		{
			name: "with dashes",
			src:  "anti-static/analysis.yara",
			rule: "static_analysis",
			want: "anti-static/analysis",
		},
		{
			name: "remove .yara extension",
			src:  "exec/exec_dylib.yara",
			rule: "dylib_test",
			want: "exec/dylib",
		},
		{
			name: "reduce stutter",
			src:  "credential/credential_access.yara",
			rule: "credential_dump",
			want: "credential/access",
		},
		{
			name: "multiple levels",
			src:  "namespace/resource/technique.yara",
			rule: "test",
			want: "namespace/resource/technique",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateKey(tt.src, tt.rule)
			if got != tt.want {
				t.Errorf("generateKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateRuleURL(t *testing.T) {
	tests := []struct {
		name string
		src  string
		rule string
		want string
	}{
		{
			name: "basic rule",
			src:  "malware/trojan.yara",
			rule: "trojan_test",
			want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/malware/trojan.yara#trojan_test",
		},
		{
			name: "nested path",
			src:  "exec/dylib/loader.yara",
			rule: "dylib_inject",
			want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/exec/dylib/loader.yara#dylib_inject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateRuleURL(tt.src, tt.rule)
			if got != tt.want {
				t.Errorf("generateRuleURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIgnoreMatch(t *testing.T) {
	tests := []struct {
		name       string
		tags       []string
		ignoreTags map[string]bool
		want       bool
	}{
		{
			name:       "no tags to ignore",
			tags:       []string{"malware", "trojan"},
			ignoreTags: map[string]bool{},
			want:       false,
		},
		{
			name:       "tag should be ignored",
			tags:       []string{"harmless", "common"},
			ignoreTags: map[string]bool{"harmless": true},
			want:       true,
		},
		{
			name:       "multiple tags one ignored",
			tags:       []string{"suspicious", "harmless"},
			ignoreTags: map[string]bool{"harmless": true, "benign": true},
			want:       true,
		},
		{
			name:       "no matching ignore tags",
			tags:       []string{"malware", "critical"},
			ignoreTags: map[string]bool{"harmless": true, "benign": true},
			want:       false,
		},
		{
			name:       "empty tags",
			tags:       []string{},
			ignoreTags: map[string]bool{"harmless": true},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ignoreMatch(tt.tags, tt.ignoreTags)
			if got != tt.want {
				t.Errorf("ignoreMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBehaviorRisk(t *testing.T) {
	tests := []struct {
		name string
		ns   string
		rule string
		tags []string
		want int
	}{
		{
			name: "third party default",
			ns:   "yara/somevendor/test.yara",
			rule: "test_rule",
			tags: []string{},
			want: HIGH,
		},
		{
			name: "low risk",
			ns:   "malware/test.yara",
			rule: "test_rule",
			tags: []string{"low"},
			want: LOW,
		},
		{
			name: "medium risk",
			ns:   "malware/test.yara",
			rule: "test_rule",
			tags: []string{"medium"},
			want: MEDIUM,
		},
		{
			name: "high risk",
			ns:   "malware/test.yara",
			rule: "test_rule",
			tags: []string{"high"},
			want: HIGH,
		},
		{
			name: "critical risk",
			ns:   "malware/test.yara",
			rule: "test_rule",
			tags: []string{"critical"},
			want: CRITICAL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := behaviorRisk(tt.ns, tt.rule, tt.tags)
			if got != tt.want {
				t.Errorf("behaviorRisk() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFixURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "url with spaces",
			url:  "https://example.com/path with spaces",
			want: "https://example.com/path%20with%20spaces",
		},
		{
			name: "url without spaces",
			url:  "https://example.com/path",
			want: "https://example.com/path",
		},
		{
			name: "empty url",
			url:  "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fixURL(tt.url)
			if got != tt.want {
				t.Errorf("fixURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMungeDescription(t *testing.T) {
	tests := []struct {
		name string
		desc string
		want string
	}{
		{
			name: "threat hunting keyword",
			desc: "Detection patterns for the tool 'Nsight RMM' taken from the ThreatHunting-Keywords github project",
			want: "references 'Nsight RMM' tool",
		},
		{
			name: "another threat hunting pattern",
			desc: "Detection patterns for the tool 'AnyDesk' taken from the ThreatHunting-Keywords github project",
			want: "references 'AnyDesk' tool",
		},
		{
			name: "normal description unchanged",
			desc: "This is a normal malware description",
			want: "This is a normal malware description",
		},
		{
			name: "empty description",
			desc: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mungeDescription(tt.desc)
			if got != tt.want {
				t.Errorf("mungeDescription() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestThirdParty(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{"third party yara path", "yara/elastic/test.yara", true},
		{"local rule", "malware/trojan.yara", false},
		{"nested yara path", "rules/yara/test.yara", true},
		{"empty path", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := thirdParty(tt.src)
			if got != tt.want {
				t.Errorf("thirdParty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"valid http url", "http://example.com", true},
		{"valid https url", "https://example.com/path", true},
		{"valid relative url", "/path/to/resource", true},
		{"valid file url", "file:///path/to/file", true},
		{"empty string", "", true},                                // url.Parse("") doesn't return error
		{"invalid url with spaces", "http://example .com", false}, // url.Parse rejects spaces in hostname
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidURL(tt.url)
			if got != tt.want {
				t.Errorf("isValidURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		prefixes []string
		want     string
	}{
		{
			name:     "remove matching prefix",
			path:     "/tmp/extract/bin/ls",
			prefixes: []string{"/tmp/extract"},
			want:     "bin/ls",
		},
		{
			name:     "no matching prefix",
			path:     "/usr/bin/ls",
			prefixes: []string{"/tmp"},
			want:     "/usr/bin/ls",
		},
		{
			name:     "private prefix",
			path:     "/private/tmp/file",
			prefixes: []string{"/private"},
			want:     "/tmp/file",
		},
		{
			name:     "relative prefix",
			path:     "/samples/test.bin",
			prefixes: []string{"./samples"},
			want:     "test.bin",
		},
		{
			name:     "empty prefix",
			path:     "/tmp/file",
			prefixes: []string{""},
			want:     "/tmp/file",
		},
		{
			name:     "multiple prefixes",
			path:     "/samples/malware/test.bin",
			prefixes: []string{"/tmp", "/samples"},
			want:     "malware/test.bin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TrimPrefixes(tt.path, tt.prefixes)
			if got != tt.want {
				t.Errorf("TrimPrefixes() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleOverrides(t *testing.T) {
	t.Parallel()

	t.Run("override lowers risk", func(t *testing.T) {
		t.Parallel()
		original := []*malcontent.Behavior{
			{RuleName: "dangerous", RiskScore: CRITICAL, RiskLevel: "CRITICAL", ID: "id1"},
			{RuleName: "safe", RiskScore: LOW, RiskLevel: "LOW", ID: "id2"},
		}
		override := []*malcontent.Behavior{
			{RuleName: "override_dangerous", RiskScore: LOW, RiskLevel: "LOW", Override: []string{"dangerous"}},
		}
		result := handleOverrides(original, override, LOW, false, false)

		for _, b := range result {
			if b.RuleName == "override_dangerous" {
				t.Error("override rule should be removed from result")
			}
			if b.RuleName == "dangerous" && b.RiskScore != LOW {
				t.Errorf("expected dangerous lowered to LOW, got %d", b.RiskScore)
			}
		}
	})

	t.Run("override raises risk", func(t *testing.T) {
		t.Parallel()
		original := []*malcontent.Behavior{
			{RuleName: "mild", RiskScore: LOW, RiskLevel: "LOW", ID: "id1"},
		}
		override := []*malcontent.Behavior{
			{RuleName: "upgrade", RiskScore: CRITICAL, RiskLevel: "CRITICAL", Override: []string{"mild"}},
		}
		result := handleOverrides(original, override, LOW, false, false)
		found := false
		for _, b := range result {
			if b.RuleName == "mild" {
				found = true
				if b.RiskScore != CRITICAL {
					t.Errorf("expected mild raised to CRITICAL, got %d", b.RiskScore)
				}
			}
		}
		if !found {
			t.Error("mild should be in result")
		}
	})

	t.Run("override non-existent rule no crash", func(t *testing.T) {
		t.Parallel()
		original := []*malcontent.Behavior{
			{RuleName: "real", RiskScore: MEDIUM, RiskLevel: "MEDIUM", ID: "id1"},
		}
		override := []*malcontent.Behavior{
			{RuleName: "bad_override", RiskScore: LOW, RiskLevel: "LOW", Override: []string{"nonexistent"}},
		}
		result := handleOverrides(original, override, LOW, false, false)
		for _, b := range result {
			if b.RuleName == "bad_override" {
				t.Error("bad_override should not appear in result")
			}
		}
	})

	t.Run("filtering by minScore non-scan", func(t *testing.T) {
		t.Parallel()
		original := []*malcontent.Behavior{
			{RuleName: "low", RiskScore: LOW, RiskLevel: "LOW", ID: "id1"},
			{RuleName: "med", RiskScore: MEDIUM, RiskLevel: "MEDIUM", ID: "id2"},
			{RuleName: "high", RiskScore: HIGH, RiskLevel: "HIGH", ID: "id3"},
		}
		result := handleOverrides(original, nil, MEDIUM, false, false)
		for _, b := range result {
			if b.RiskScore < MEDIUM {
				t.Errorf("%q with score %d should be filtered", b.RuleName, b.RiskScore)
			}
		}
		if len(result) != 2 {
			t.Errorf("expected 2 behaviors, got %d", len(result))
		}
	})

	t.Run("scan+quantityIncreasesRisk filters below HIGH", func(t *testing.T) {
		t.Parallel()
		original := []*malcontent.Behavior{
			{RuleName: "low", RiskScore: LOW, ID: "id1"},
			{RuleName: "med", RiskScore: MEDIUM, ID: "id2"},
			{RuleName: "high", RiskScore: HIGH, ID: "id3"},
			{RuleName: "crit", RiskScore: CRITICAL, ID: "id4"},
		}
		result := handleOverrides(original, nil, LOW, true, true)
		for _, b := range result {
			if b.RiskScore < HIGH {
				t.Errorf("%q score %d should be filtered in scan+QIR", b.RuleName, b.RiskScore)
			}
		}
		if len(result) != 2 {
			t.Errorf("expected 2 behaviors, got %d", len(result))
		}
	})

	t.Run("empty slices", func(t *testing.T) {
		t.Parallel()
		result := handleOverrides(nil, nil, LOW, false, false)
		if len(result) != 0 {
			t.Errorf("expected empty, got %d", len(result))
		}
	})

	t.Run("override removes itself from map", func(t *testing.T) {
		t.Parallel()
		original := []*malcontent.Behavior{
			{RuleName: "real", RiskScore: HIGH, RiskLevel: "HIGH", ID: "id1"},
			{RuleName: "override_rule", RiskScore: MEDIUM, RiskLevel: "MEDIUM", ID: "id2"},
		}
		override := []*malcontent.Behavior{
			{RuleName: "override_rule", RiskScore: LOW, RiskLevel: "LOW", Override: []string{"real"}},
		}
		result := handleOverrides(original, override, LOW, false, false)
		for _, b := range result {
			if b.RuleName == "override_rule" {
				t.Error("override rule should be deleted")
			}
		}
	})

	t.Run("override that lowers below minScore filters behavior", func(t *testing.T) {
		t.Parallel()
		original := []*malcontent.Behavior{
			{RuleName: "target", RiskScore: HIGH, RiskLevel: "HIGH", ID: "id1"},
		}
		override := []*malcontent.Behavior{
			{RuleName: "downgrade", RiskScore: HARMLESS, RiskLevel: "NONE", Override: []string{"target"}},
		}
		result := handleOverrides(original, override, MEDIUM, false, false)
		if len(result) != 0 {
			t.Errorf("expected 0 after override lowered below minScore, got %d", len(result))
		}
	})

	t.Run("override with multiple targets", func(t *testing.T) {
		t.Parallel()
		original := []*malcontent.Behavior{
			{RuleName: "a", RiskScore: HIGH, RiskLevel: "HIGH", ID: "id1"},
			{RuleName: "b", RiskScore: HIGH, RiskLevel: "HIGH", ID: "id2"},
			{RuleName: "c", RiskScore: MEDIUM, RiskLevel: "MEDIUM", ID: "id3"},
		}
		override := []*malcontent.Behavior{
			{RuleName: "multi", RiskScore: LOW, RiskLevel: "LOW", Override: []string{"a", "b"}},
		}
		result := handleOverrides(original, override, LOW, false, false)
		for _, b := range result {
			if (b.RuleName == "a" || b.RuleName == "b") && b.RiskScore != LOW {
				t.Errorf("%q should be overridden to LOW, got %d", b.RuleName, b.RiskScore)
			}
			if b.RuleName == "c" && b.RiskScore != MEDIUM {
				t.Errorf("c should be unchanged at MEDIUM, got %d", b.RiskScore)
			}
		}
	})

	t.Run("result never longer than original", func(t *testing.T) {
		t.Parallel()
		original := make([]*malcontent.Behavior, 20)
		for i := range 20 {
			original[i] = &malcontent.Behavior{
				RuleName:  "rule_" + strings.Repeat("a", i+1),
				RiskScore: HIGH, RiskLevel: "HIGH",
				ID: "id_" + strings.Repeat("a", i+1),
			}
		}
		result := handleOverrides(original, nil, LOW, false, false)
		if len(result) > len(original) {
			t.Errorf("result %d exceeds original %d", len(result), len(original))
		}
	})
}

func TestUpdateBehavior(t *testing.T) {
	t.Parallel()

	t.Run("new behavior appended", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{ID: "existing", RiskScore: LOW}},
		}
		updateBehavior(fr, &malcontent.Behavior{ID: "new_id", RiskScore: MEDIUM, Description: "new"}, "new_id")
		if len(fr.Behaviors) != 2 {
			t.Fatalf("expected 2, got %d", len(fr.Behaviors))
		}
		if fr.Behaviors[1].ID != "new_id" {
			t.Errorf("expected new_id at index 1, got %q", fr.Behaviors[1].ID)
		}
	})

	t.Run("higher risk replaces", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{ID: "rule_a", RiskScore: LOW, Description: "original"}},
		}
		updateBehavior(fr, &malcontent.Behavior{ID: "rule_a", RiskScore: CRITICAL, Description: "upgraded"}, "rule_a")
		if len(fr.Behaviors) != 1 || fr.Behaviors[0].RiskScore != CRITICAL {
			t.Errorf("expected CRITICAL replacement, got %+v", fr.Behaviors)
		}
	})

	t.Run("same risk longer description updates", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{ID: "rule_b", RiskScore: MEDIUM, Description: "short"}},
		}
		updateBehavior(fr, &malcontent.Behavior{ID: "rule_b", RiskScore: MEDIUM, Description: "a much longer description"}, "rule_b")
		if fr.Behaviors[0].Description != "a much longer description" {
			t.Errorf("description not updated: %q", fr.Behaviors[0].Description)
		}
		if fr.Behaviors[0].RiskScore != MEDIUM {
			t.Errorf("risk should stay MEDIUM, got %d", fr.Behaviors[0].RiskScore)
		}
	})

	t.Run("lower risk does not replace", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{ID: "rule_c", RiskScore: HIGH, Description: "original"}},
		}
		updateBehavior(fr, &malcontent.Behavior{ID: "rule_c", RiskScore: LOW, Description: "low"}, "rule_c")
		if fr.Behaviors[0].RiskScore != HIGH || fr.Behaviors[0].Description != "original" {
			t.Errorf("should be unchanged, got score=%d desc=%q", fr.Behaviors[0].RiskScore, fr.Behaviors[0].Description)
		}
	})

	t.Run("higher risk replaces at correct index", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{
				{ID: "first", RiskScore: LOW},
				{ID: "target", RiskScore: MEDIUM},
				{ID: "third", RiskScore: LOW},
			},
		}
		updateBehavior(fr, &malcontent.Behavior{ID: "target", RiskScore: CRITICAL}, "target")
		if len(fr.Behaviors) != 3 {
			t.Fatalf("expected 3, got %d", len(fr.Behaviors))
		}
		if fr.Behaviors[1].RiskScore != CRITICAL {
			t.Errorf("index 1 should be CRITICAL, got %d", fr.Behaviors[1].RiskScore)
		}
		if fr.Behaviors[0].ID != "first" || fr.Behaviors[2].ID != "third" {
			t.Error("neighbors should be undisturbed")
		}
	})
}

func TestHighestBehaviorRisk(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		fr   *malcontent.FileReport
		want int
	}{
		{"nil report", nil, 0},
		{"empty behaviors", &malcontent.FileReport{}, 0},
		{"single", &malcontent.FileReport{Behaviors: []*malcontent.Behavior{{RiskScore: MEDIUM}}}, MEDIUM},
		{"multiple returns max", &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{RiskScore: LOW}, {RiskScore: CRITICAL}, {RiskScore: MEDIUM}},
		}, CRITICAL},
		{"all same", &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{RiskScore: HIGH}, {RiskScore: HIGH}},
		}, HIGH},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := highestBehaviorRisk(tt.fr); got != tt.want {
				t.Errorf("highestBehaviorRisk() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMatchToString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ruleName string
		match    string
		want     string
	}{
		{"unprintable returns ruleName", "rule", "\x01\x02\x03", "rule"},
		{"base64 uses :: format", "base64_encode", "payload", "base64_encode::payload"},
		{"xor uses :: format", "xor_key", "data", "xor_key::data"},
		{"xml_key_val strips tags", "xml_key_val_test", "<key>test</key>", "test"},
		{"normal trims", "normal", "  match  ", "match"},
		{"empty match trimmed", "rule", "   ", ""},
		{"tab is unprintable", "rule", "\ttabs", "rule"},
		{"spaces only trimmed", "rule", "   spaces   ", "spaces"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := matchToString(tt.ruleName, tt.match)
			if got != tt.want {
				t.Errorf("matchToString(%q, %q) = %q, want %q", tt.ruleName, tt.match, got, tt.want)
			}
		})
	}
}

func TestFindSeparator(t *testing.T) {
	t.Parallel()

	t.Run("empty input returns 0", func(t *testing.T) {
		t.Parallel()
		if got := findSeparator(nil); got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
	})

	t.Run("skips byte 0 when used", func(t *testing.T) {
		t.Parallel()
		got := findSeparator([]string{string([]byte{0})})
		if got != 1 {
			t.Errorf("expected 1, got %d", got)
		}
	})

	t.Run("all but byte 42 used returns 42", func(t *testing.T) {
		t.Parallel()
		b := make([]byte, 0, 255)
		for i := range 256 {
			if i == 42 {
				continue
			}
			b = append(b, byte(i))
		}
		if got := findSeparator([]string{string(b)}); got != 42 {
			t.Errorf("expected 42, got %d", got)
		}
	})

	t.Run("all 256 bytes used returns 0", func(t *testing.T) {
		t.Parallel()
		b := make([]byte, 256)
		for i := range 256 {
			b[i] = byte(i)
		}
		if got := findSeparator([]string{string(b)}); got != 0 {
			t.Errorf("expected 0 fallback, got %d", got)
		}
	})

	t.Run("multiple strings cover 0-9", func(t *testing.T) {
		t.Parallel()
		strs := make([]string, 10)
		for i := range 10 {
			strs[i] = string([]byte{byte(i)})
		}
		if got := findSeparator(strs); got != 10 {
			t.Errorf("expected 10, got %d", got)
		}
	})
}
