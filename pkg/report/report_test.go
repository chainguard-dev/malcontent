// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"io/fs"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/release"
	"github.com/chainguard-dev/malcontent/rules"
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
			if got := longestUnique(slices.Clone(tt.raw)); !reflect.DeepEqual(got, tt.want) {
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
	// longestUnique reorders its input, so each iteration starts from a copy.
	buf := make([]string, len(raw))
	b.ReportAllocs()
	for b.Loop() {
		copy(buf, raw)
		longestUnique(buf)
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
		{"large-default-threshold", 3, map[int]int{3: 6}, 1024 * 1024 * 1024, true},
		{"large-below-threshold", 3, map[int]int{3: 5}, 1024 * 1024 * 1024, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := upgradeRisk(t.Context(), tt.currentScore, tt.riskCounts[HIGH], tt.size); got != tt.want {
				t.Errorf("upgradeRisk(%d, %v, %v) = %v, want %v", tt.currentScore, tt.riskCounts, tt.size, got, tt.want)
			}
		})
	}
}

func TestUpgradeRisk_BandPartition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		size       int64
		riskCounts map[int]int
		want       bool
	}{
		{name: "band1 sub-KiB highCount=2 upgrades", size: 1000, riskCounts: map[int]int{3: 2}, want: true},
		{name: "band1 sub-KiB highCount=1 no upgrade", size: 1000, riskCounts: map[int]int{3: 1}, want: false},
		{name: "1023 bytes highCount=2 upgrades", size: 1023, riskCounts: map[int]int{3: 2}, want: true},
		{name: "1024 bytes highCount=2 no upgrade", size: 1024, riskCounts: map[int]int{3: 2}, want: false},
		{name: "1024 bytes highCount=3 upgrades", size: 1024, riskCounts: map[int]int{3: 3}, want: true},
		{name: "sub-MiB highCount=2 no upgrade", size: 500 * 1024, riskCounts: map[int]int{3: 2}, want: false},
		{name: "sub-MiB highCount=3 upgrades", size: 500 * 1024, riskCounts: map[int]int{3: 3}, want: true},
		{name: "1048575 bytes highCount=2 no upgrade", size: 1048575, riskCounts: map[int]int{3: 2}, want: false},
		{name: "1048575 bytes highCount=3 upgrades", size: 1048575, riskCounts: map[int]int{3: 3}, want: true},
		{name: "1048576 bytes highCount=2 no upgrade", size: 1048576, riskCounts: map[int]int{3: 2}, want: false},
		{name: "1048576 bytes highCount=3 upgrades", size: 1048576, riskCounts: map[int]int{3: 3}, want: true},
		{name: "band2 1.5MB highCount=3 upgrades", size: int64(1.5 * 1024 * 1024), riskCounts: map[int]int{3: 3}, want: true},
		{name: "band2 1.5MB highCount=2 no upgrade", size: int64(1.5 * 1024 * 1024), riskCounts: map[int]int{3: 2}, want: false},
		{name: "band3 3MB highCount=4 upgrades", size: 3 * 1024 * 1024, riskCounts: map[int]int{3: 4}, want: true},
		{name: "band4 5MB highCount=5 upgrades", size: 5 * 1024 * 1024, riskCounts: map[int]int{3: 5}, want: true},
		{name: "band4 5MB highCount=4 no upgrade", size: 5 * 1024 * 1024, riskCounts: map[int]int{3: 4}, want: false},
		{name: "default 20MB highCount=6 upgrades", size: 20 * 1024 * 1024, riskCounts: map[int]int{3: 6}, want: true},
		{name: "default 20MB highCount=5 no upgrade", size: 20 * 1024 * 1024, riskCounts: map[int]int{3: 5}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := upgradeRisk(t.Context(), HIGH, tt.riskCounts[HIGH], tt.size); got != tt.want {
				t.Errorf("upgradeRisk(HIGH, %v, %d) = %v, want %v", tt.riskCounts, tt.size, got, tt.want)
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
			if got := applyCriticalUpgrade(t.Context(), tt.quantityIncreasesRisk, tt.riskCounts[HIGH], tt.overallRiskScore, tt.size); got != tt.want {
				t.Errorf("applyCriticalUpgrade(ctx, %v, %v, %d, %d) = %v, want %v", tt.quantityIncreasesRisk, tt.riskCounts, tt.overallRiskScore, tt.size, got, tt.want)
			}
		})
	}
}

func TestIsSelf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		checksum string
		want     bool
	}{
		{"the running executable's digest is malcontent", runningBinarySHA256(t), true},
		{"another digest is not", strings.Repeat("0", 64), false},
		{"a placeholder digest is not", "cksum", false},
		{"an empty digest is not", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isSelf(tt.checksum); got != tt.want {
				t.Errorf("isSelf(%q): got = %v, want = %v", tt.checksum, got, tt.want)
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
		{
			name: "resource inside the technique leaves a single underscore",
			src:  "net/proxy/socks_proxy_client.yara",
			rule: "socks_proxy",
			want: "net/proxy/socks_client",
		},
		{
			name: "removing the resource from the technique leaves no .yara behind",
			src:  "ns/res/.yaresra",
			rule: "test",
			want: "ns/res",
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

// sharedKeys returns, for each behavior ID that more than one rule file in
// fsys produces, the files that produce it. Every rule of a first-party file
// shares the file's ID, so files that share an ID merge their behaviors.
func sharedKeys(t *testing.T, fsys fs.FS) map[string][]string {
	t.Helper()
	byKey := map[string][]string{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yara" {
			return err
		}
		key := generateKey(path, "rule")
		byKey[key] = append(byKey[key], path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk rules: %v", err)
	}
	maps.DeleteFunc(byKey, func(_ string, files []string) bool { return len(files) < 2 })
	return byKey
}

func TestGenerateKeyUniquePerRuleFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		fsys fs.FS
		want map[string][]string
	}{
		{
			name: "files whose names reduce to one ID are reported",
			fsys: fstest.MapFS{
				"net/ip/ip-spoof.yara": {},
				"net/ip/spoof.yara":    {},
				"net/ip/addr.yara":     {},
			},
			want: map[string][]string{"net/ip/spoof": {"net/ip/ip-spoof.yara", "net/ip/spoof.yara"}},
		},
		{
			name: "files with distinct IDs report nothing",
			fsys: fstest.MapFS{"net/ip/spoof-tool.yara": {}, "net/ip/spoof.yara": {}},
			want: map[string][]string{},
		},
		{name: "the bundled rules give every file its own ID", fsys: rules.FS, want: map[string][]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sharedKeys(t, tt.fsys); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("shared behavior IDs: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

// withBuildCommit sets release.BuildCommit for the lifetime of the test
// and restores the prior value via t.Cleanup. The package-level variable
// is mutated directly because release does not expose a setter.
func withBuildCommit(t *testing.T, v string) {
	t.Helper()
	prev := release.BuildCommit
	release.BuildCommit = v
	t.Cleanup(func() { release.BuildCommit = prev })
}

func TestGenerateRuleURL(t *testing.T) {
	// Pin BuildCommit so the assertion is deterministic regardless of the
	// host's go test build-info VCS state.
	const sha = "0123456789abcdef0123456789abcdef01234567"
	withBuildCommit(t, sha)

	tests := []struct {
		name string
		src  string
		rule string
		want string
	}{
		{
			name: "known rule maps to line anchor",
			src:  "sus/leetspeak.yara",
			rule: "one_three_three_seven",
			want: "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/rules/sus/leetspeak.yara#L1",
		},
		{
			name: "unknown rule falls back to name anchor",
			src:  "malware/trojan.yara",
			rule: "trojan_test",
			want: "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/rules/malware/trojan.yara#trojan_test",
		},
		{
			// third_party rules live under third_party/, not rules/
			name: "third_party_jpcert_rule",
			src:  "yara/JPCERT/lazarus.yara",
			rule: "Lazarus_jamistealer_str",
			want: "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/third_party/yara/JPCERT/lazarus.yara#Lazarus_jamistealer_str",
		},
		{
			name: "third_party_elastic_rule",
			src:  "yara/elastic/MacOS_Trojan_BeaverTail.yar",
			rule: "MacOS_Trojan_BeaverTail_90b8abd6",
			want: "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/third_party/yara/elastic/MacOS_Trojan_BeaverTail.yar#MacOS_Trojan_BeaverTail_90b8abd6",
		},
		{
			name: "first_party_unchanged",
			src:  "malware/trojan.yara",
			rule: "Trojan_Generic",
			want: "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/rules/malware/trojan.yara#Trojan_Generic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateRuleURL(release.ResolveRuleURLCommit(), tt.src, tt.rule)
			if got != tt.want {
				t.Errorf("generateRuleURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateRuleURL_CommitPinned(t *testing.T) {
	const sha = "abcdef0123456789abcdef0123456789abcdef01"

	tests := []struct {
		name        string
		buildCommit string
		src         string
		rule        string
		want        string
	}{
		{
			name:        "build commit set with map hit",
			buildCommit: sha,
			src:         "sus/leetspeak.yara",
			rule:        "too_l33t_for_me",
			want:        "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/rules/sus/leetspeak.yara#L13",
		},
		{
			name:        "build commit empty falls back to main",
			buildCommit: "",
			src:         "sus/leetspeak.yara",
			rule:        "one_three_three_seven",
			want:        "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1",
		},
		{
			name:        "map miss yields name anchor",
			buildCommit: sha,
			src:         "sus/leetspeak.yara",
			rule:        "no_such_rule_anywhere",
			want:        "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/rules/sus/leetspeak.yara#no_such_rule_anywhere",
		},
		{
			name:        "non-hex build commit rejected, falls back to main",
			buildCommit: "not-a-sha-just-some-text-here-padding-12",
			src:         "sus/leetspeak.yara",
			rule:        "one_three_three_seven",
			want:        "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1",
		},
		{
			name:        "empty src still produces a URL",
			buildCommit: sha,
			src:         "",
			rule:        "anything",
			want:        "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/rules/#anything",
		},
		{
			name:        "third_party_jpcert_with_commit",
			buildCommit: sha,
			src:         "yara/JPCERT/lazarus.yara",
			rule:        "Lazarus_jamistealer_str",
			want:        "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/third_party/yara/JPCERT/lazarus.yara#Lazarus_jamistealer_str",
		},
		{
			name:        "third_party_elastic_falls_back_to_main",
			buildCommit: "",
			src:         "yara/elastic/MacOS_Trojan_BeaverTail.yar",
			rule:        "MacOS_Trojan_BeaverTail_90b8abd6",
			want:        "https://github.com/chainguard-dev/malcontent/blob/main/third_party/yara/elastic/MacOS_Trojan_BeaverTail.yar#MacOS_Trojan_BeaverTail_90b8abd6",
		},
		{
			name:        "first_party_with_commit_unchanged",
			buildCommit: sha,
			src:         "malware/trojan.yara",
			rule:        "Trojan_Generic",
			want:        "https://github.com/chainguard-dev/malcontent/blob/" + sha + "/rules/malware/trojan.yara#Trojan_Generic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withBuildCommit(t, tt.buildCommit)
			got := generateRuleURL(release.ResolveRuleURLCommit(), tt.src, tt.rule)
			if got != tt.want {
				t.Errorf("generateRuleURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRuleLineIndex_BuildsForAllRules(t *testing.T) {
	// Independently walk the embedded rules FS and gather every
	// (src, rule_name) pair. The index under test must contain each.
	type ruleKey struct {
		src  string
		rule string
	}

	var discovered []ruleKey
	err := fs.WalkDir(rules.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yara" && ext != ".yar" {
			return nil
		}
		bs, err := fs.ReadFile(rules.FS, path)
		if err != nil {
			return err
		}
		for line := range strings.SplitSeq(string(bs), "\n") {
			// match `^rule\s+(\w+)` semantics for the verification loop
			if !strings.HasPrefix(line, "rule") {
				continue
			}
			rest := strings.TrimPrefix(line, "rule")
			if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
				continue
			}
			rest = strings.TrimLeft(rest, " \t")
			end := 0
			for end < len(rest) {
				c := rest[end]
				if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
					end++
					continue
				}
				break
			}
			if end == 0 {
				continue
			}
			discovered = append(discovered, ruleKey{src: path, rule: rest[:end]})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking rules.FS: %v", err)
	}

	if len(discovered) == 0 {
		t.Fatalf("walk found zero rules; the embed must contain at least one")
	}
	const upperBound = 2300
	if len(discovered) > upperBound {
		t.Fatalf("walk found %d rules, exceeds upper bound %d", len(discovered), upperBound)
	}

	slices.SortFunc(discovered, func(a, b ruleKey) int {
		if a.src != b.src {
			return strings.Compare(a.src, b.src)
		}
		return strings.Compare(a.rule, b.rule)
	})

	for _, k := range discovered {
		line, ok := ruleLine(k.src, k.rule)
		if !ok {
			t.Errorf("ruleLine(%q, %q): not found in index", k.src, k.rule)
			continue
		}
		if line <= 0 {
			t.Errorf("ruleLine(%q, %q) = %d; want positive", k.src, k.rule, line)
		}
	}
}

// TestResolveCommit_PriorityChain exercises the resolver indirectly through
// generateRuleURL. Each row alters release.BuildCommit and asserts the URL
// scheme chosen by the resolver.
func TestResolveCommit_PriorityChain(t *testing.T) {
	const validSHA = "abcdef0123456789abcdef0123456789abcdef01"

	tests := []struct {
		name        string
		buildCommit string
		want        string
	}{
		{name: "valid hex sha accepted", buildCommit: validSHA, want: "https://github.com/chainguard-dev/malcontent/blob/" + validSHA + "/rules/sus/leetspeak.yara#L1"},
		{name: "empty falls back to main", buildCommit: "", want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1"},
		{name: "uppercase rejected", buildCommit: strings.ToUpper(validSHA), want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1"},
		{name: "short rejected", buildCommit: validSHA[:39], want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1"},
		{name: "long rejected", buildCommit: validSHA + "0", want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withBuildCommit(t, tt.buildCommit)
			got := generateRuleURL(release.ResolveRuleURLCommit(), "sus/leetspeak.yara", "one_three_three_seven")
			if got != tt.want {
				t.Errorf("generateRuleURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateRuleURL_FallbackOnNonCanonical(t *testing.T) {
	tests := []struct {
		name        string
		buildCommit string
		want        string
	}{
		{name: "empty_falls_back_to_main", buildCommit: "", want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1"},
		{name: "short_hex_falls_back_to_main", buildCommit: "abcdef0", want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1"},
		{name: "mixed_case_falls_back_to_main", buildCommit: "ABCDEF0123456789ABCDEF0123456789ABCDEF01", want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1"},
		{name: "forty_one_hex_falls_back_to_main", buildCommit: "abcdef0123456789abcdef0123456789abcdef010", want: "https://github.com/chainguard-dev/malcontent/blob/main/rules/sus/leetspeak.yara#L1"},
		{name: "valid_lower_hex_emits_url", buildCommit: "abcdef0123456789abcdef0123456789abcdef01", want: "https://github.com/chainguard-dev/malcontent/blob/abcdef0123456789abcdef0123456789abcdef01/rules/sus/leetspeak.yara#L1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withBuildCommit(t, tt.buildCommit)
			got := generateRuleURL(release.ResolveRuleURLCommit(), "sus/leetspeak.yara", "one_three_three_seven")
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
		ignoreTags map[string]struct{}
		want       bool
	}{
		{
			name:       "no tags to ignore",
			tags:       []string{"malware", "trojan"},
			ignoreTags: map[string]struct{}{},
			want:       false,
		},
		{
			name:       "tag should be ignored",
			tags:       []string{tagHarmless, "common"},
			ignoreTags: map[string]struct{}{tagHarmless: {}},
			want:       true,
		},
		{
			name:       "multiple tags one ignored",
			tags:       []string{"suspicious", tagHarmless},
			ignoreTags: map[string]struct{}{tagHarmless: {}, "benign": {}},
			want:       true,
		},
		{
			name:       "no matching ignore tags",
			tags:       []string{"malware", "critical"},
			ignoreTags: map[string]struct{}{tagHarmless: {}, "benign": {}},
			want:       false,
		},
		{
			name:       "empty tags",
			tags:       []string{},
			ignoreTags: map[string]struct{}{tagHarmless: {}},
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
			want: `references "Nsight RMM" tool`,
		},
		{
			name: "another threat hunting pattern",
			desc: "Detection patterns for the tool 'AnyDesk' taken from the ThreatHunting-Keywords github project",
			want: `references "AnyDesk" tool`,
		},
		{
			name: "tool name with a quote, backslash, and tab is escaped",
			desc: "Detection patterns for the tool 'a\"b\\c\td' taken from the ThreatHunting-Keywords github project",
			want: `references "a\"b\\c\td" tool`,
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
		{"nested yara reference is not third-party", "rules/yara/test.yara", false},
		{"prefix yara is third-party", "yara/feed/rule", true},
		{"contains yara mid-path is not third-party", "internal/yara/foo", false},
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

func TestDisplayPath(t *testing.T) {
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
		{
			name:     "empty prefix before a matching prefix",
			path:     "/samples/malware/test.bin",
			prefixes: []string{"", "/samples"},
			want:     "malware/test.bin",
		},
		{
			name:     "bare dot slash prefix before a matching prefix",
			path:     "/samples/malware/test.bin",
			prefixes: []string{"./", "/samples"},
			want:     "malware/test.bin",
		},
		{
			name:     "absolute prefix does not match a path with a doubled leading slash",
			path:     "//samples/test.bin",
			prefixes: []string{"/samples"},
			want:     "//samples/test.bin",
		},
		{name: "macOS private var is displayed as var", path: "/private/var/folders/x/f", want: "/var/folders/x/f"},
		{name: "macOS private tmp is displayed as tmp", path: "/private/tmp", want: "/tmp"},
		{name: "macOS private etc is displayed as etc", path: "/private/etc/hosts", want: "/etc/hosts"},
		{name: "other private directories keep the prefix", path: "/private/foo/bar", want: "/private/foo/bar"},
		{name: "private prefix ends at a directory boundary", path: "/private/variable/x", want: "/private/variable/x"},
		{name: "resolved prefix trims an unresolved path", path: "/var/x/a.zip", prefixes: []string{"/private/var/x"}, want: "a.zip"},
		{name: "unresolved prefix trims a resolved path", path: "/private/var/x/a.zip", prefixes: []string{"/var/x"}, want: "a.zip"},
		{name: "prefixes after a private prefix are tried", path: "/srv/x/f", prefixes: []string{"/private", "/srv/x"}, want: "f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DisplayPath(tt.path, tt.prefixes)
			if got != tt.want {
				t.Errorf("DisplayPath(%q, %q): got = %q, want = %q", tt.path, tt.prefixes, got, tt.want)
			}
		})
	}
}

func TestUpdateBehavior(t *testing.T) {
	t.Parallel()

	t.Run("new behavior appended", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{ID: "existing", RiskScore: LOW}},
		}
		if got := updateBehaviorIndexed(fr, &malcontent.Behavior{ID: "new_id", RiskScore: MEDIUM, Description: "new"}, "new_id"); got != 1 {
			t.Errorf("index: got = %d, want = 1", got)
		}
		if len(fr.Behaviors) != 2 {
			t.Fatalf("behaviors: got = %d, want = 2", len(fr.Behaviors))
		}
		if fr.Behaviors[1].ID != "new_id" {
			t.Errorf("Behaviors[1].ID: got = %q, want = %q", fr.Behaviors[1].ID, "new_id")
		}
	})

	t.Run("higher risk replaces", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{ID: "rule_a", RiskScore: LOW, Description: "original"}},
		}
		if got := updateBehaviorIndexed(fr, &malcontent.Behavior{ID: "rule_a", RiskScore: CRITICAL, Description: "upgraded"}, "rule_a"); got != 0 {
			t.Errorf("index: got = %d, want = 0", got)
		}
		if len(fr.Behaviors) != 1 || fr.Behaviors[0].RiskScore != CRITICAL {
			t.Errorf("behaviors: got = %+v, want = one CRITICAL entry", fr.Behaviors)
		}
	})

	t.Run("same risk keeps the existing description", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{ID: "rule_b", RiskScore: MEDIUM, Description: "short"}},
		}
		if got := updateBehaviorIndexed(fr, &malcontent.Behavior{ID: "rule_b", RiskScore: MEDIUM, Description: "a much longer description"}, "rule_b"); got != -1 {
			t.Errorf("index: got = %d, want = -1", got)
		}
		if fr.Behaviors[0].Description != "short" {
			t.Errorf("Description: got = %q, want = %q", fr.Behaviors[0].Description, "short")
		}
		if fr.Behaviors[0].RiskScore != MEDIUM {
			t.Errorf("RiskScore: got = %d, want = %d", fr.Behaviors[0].RiskScore, MEDIUM)
		}
	})

	t.Run("lower risk does not replace", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{
			Behaviors: []*malcontent.Behavior{{ID: "rule_c", RiskScore: HIGH, Description: "original"}},
		}
		if got := updateBehaviorIndexed(fr, &malcontent.Behavior{ID: "rule_c", RiskScore: LOW, Description: "low"}, "rule_c"); got != -1 {
			t.Errorf("index: got = %d, want = -1", got)
		}
		if fr.Behaviors[0].RiskScore != HIGH || fr.Behaviors[0].Description != "original" {
			t.Errorf("behavior: got = score %d desc %q, want = score %d desc %q", fr.Behaviors[0].RiskScore, fr.Behaviors[0].Description, HIGH, "original")
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
		if got := updateBehaviorIndexed(fr, &malcontent.Behavior{ID: "target", RiskScore: CRITICAL}, "target"); got != 1 {
			t.Errorf("index: got = %d, want = 1", got)
		}
		if len(fr.Behaviors) != 3 {
			t.Fatalf("behaviors: got = %d, want = 3", len(fr.Behaviors))
		}
		if fr.Behaviors[1].RiskScore != CRITICAL {
			t.Errorf("Behaviors[1].RiskScore: got = %d, want = %d", fr.Behaviors[1].RiskScore, CRITICAL)
		}
		if fr.Behaviors[0].ID != "first" || fr.Behaviors[2].ID != "third" {
			t.Errorf("neighbor IDs: got = %q, %q, want = %q, %q", fr.Behaviors[0].ID, fr.Behaviors[2].ID, "first", "third")
		}
	})
}

func TestUpdateBehavior_Idempotence(t *testing.T) {
	t.Parallel()

	fr := &malcontent.FileReport{
		Behaviors: []*malcontent.Behavior{},
	}
	b := &malcontent.Behavior{ID: "same_key", RiskScore: MEDIUM, Description: "stable"}
	idx := map[string]int{}

	updateBehavior(fr, b, "same_key", idx)
	updateBehavior(fr, b, "same_key", idx)
	updateBehavior(fr, b, "same_key", idx)

	if len(fr.Behaviors) != 1 {
		t.Errorf("behaviors after 3 identical updates: got = %d, want = 1", len(fr.Behaviors))
	}
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
		{"escaped bytes are kept", "rule", `\x01\x02\x03`, `\x01\x02\x03`},
		{"base64 uses :: format", "base64_encode", "payload", "base64_encode::payload"},
		{"xor uses :: format", "xor_key", "data", "xor_key::data"},
		{"xor prefixes escaped bytes", "xor_key", `\x00\x01`, `xor_key::\x00\x01`},
		{"xml_key_val strips tags", "xml_key_val_test", "<key>test</key>", "test"},
		{"normal trims", "normal", "  match  ", "match"},
		{"empty match trimmed", "rule", "   ", ""},
		{"escaped tab is kept", "rule", `\ttabs`, `\ttabs`},
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
			t.Errorf("findSeparator: got = %d, want = 0", got)
		}
	})

	t.Run("skips byte 0 when used", func(t *testing.T) {
		t.Parallel()
		got := findSeparator([]string{string([]byte{0})})
		if got != 1 {
			t.Errorf("findSeparator: got = %d, want = 1", got)
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
			t.Errorf("findSeparator: got = %d, want = 42", got)
		}
	})

	t.Run("all 256 bytes used returns 0", func(t *testing.T) {
		t.Parallel()
		b := make([]byte, 256)
		for i := range 256 {
			b[i] = byte(i)
		}
		if got := findSeparator([]string{string(b)}); got != 0 {
			t.Errorf("findSeparator fallback: got = %d, want = 0", got)
		}
	})

	t.Run("multiple strings cover 0-9", func(t *testing.T) {
		t.Parallel()
		strs := make([]string, 10)
		for i := range 10 {
			strs[i] = string([]byte{byte(i)})
		}
		if got := findSeparator(strs); got != 10 {
			t.Errorf("findSeparator: got = %d, want = 10", got)
		}
	})
}
