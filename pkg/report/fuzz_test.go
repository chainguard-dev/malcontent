// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// FuzzLongestUnique tests the longestUnique function with random string inputs.
func FuzzLongestUnique(f *testing.F) {
	f.Add("apple,banana,cherry,applecherry,bananaapple,cherrybanana")
	f.Add("test,testing,tester,testest")
	f.Add(",a,aa,aaa")
	f.Add("abc,def,ghi")
	f.Add("abc,abcabc,abcabcabc")
	f.Add("")                                              // empty input
	f.Add("single")                                        // single string
	f.Add("a,a,a,a")                                       // all duplicates
	f.Add("very_long_string_" + strings.Repeat("x", 1000)) // long strings
	f.Add(strings.Repeat("a,", 100))                       // many strings
	f.Add("a,b,c,d,e,f,g,h,i,j,k,l,m")                     // many different strings
	f.Add("test\x00null,normal")                           // null byte
	f.Add("test\nnewline,test\rcarriage,test\ttab")        // whitespace control chars
	f.Add("test\x01\x02\x03,normal")                       // low control characters
	f.Add("test\x7f\x80\x9f,normal")                       // high control characters
	f.Add("test\u200b,normal")                             // zero-width space
	f.Add("test\u200c,normal")                             // zero-width non-joiner
	f.Add("test\u200d,normal")                             // zero-width joiner
	f.Add("test\ufeff,normal")                             // zero-width no-break space (BOM)
	f.Add("test\u202a\u202b\u202c,normal")                 // bidirectional text marks
	f.Add("test\u2060,normal")                             // word joiner
	f.Add("hello\u200bworld,helloworld")                   // same word with/without zero-width
	f.Add("test\u034f,normal")                             // combining grapheme joiner
	f.Add("\u200b\u200c\u200d,visible")                    // only invisible characters
	f.Add("a\u0300\u0301\u0302,a")                         // combining diacritical marks
	f.Add("test\u00ad,test")                               // soft hyphen
	f.Add("fi\ufb01,fi")                                   // ligature vs normal chars
	f.Add("test\u180e,normal")                             // mongolian vowel separator
	f.Add("\u061c\u2066\u2067\u2068\u2069,normal")         // directional formatting

	f.Fuzz(func(t *testing.T, input string) {
		var strs []string
		if input != "" {
			strs = strings.Split(input, ",")
		}

		result := longestUnique(strs)

		for _, s := range result {
			if s == "" {
				t.Fatal("result contains empty string")
			}
		}

		for i, s1 := range result {
			for j, s2 := range result {
				if i != j && strings.Contains(s1, s2) {
					t.Fatalf("result[%d]=%q contains result[%d]=%q", i, s1, j, s2)
				}
			}
		}

		inputMap := make(map[string]bool)
		for _, s := range strs {
			if s != "" {
				inputMap[s] = true
			}
		}
		for _, s := range result {
			if !inputMap[s] {
				t.Fatalf("result contains %q which was not in input", s)
			}
		}

		if len(result) > len(strs) {
			t.Fatalf("result length %d exceeds input length %d", len(result), len(strs))
		}
	})
}

// FuzzTrimPrefixes tests the TrimPrefixes function with random inputs.
func FuzzTrimPrefixes(f *testing.F) {
	f.Add("/tmp/extract/path/to/file", "/tmp/extract")
	f.Add("/home/user/file", "/home/user,/tmp")
	f.Add("/absolute/path", "/absolute,./relative")
	f.Add("/path/to/file", "/path/to")
	f.Add("./relative/path", "./relative")
	f.Add("./path/to/file", "./path")
	f.Add("./a/b/c/d/e", "./a/b")
	f.Add("../path/to/file", "../path/to")
	f.Add("../../parent/path", "../../parent")
	f.Add("../../../deeply/nested", "../../../deeply")
	f.Add("./././path", "./")
	f.Add("path/../other/file", "path/..")
	f.Add("relative/path", "/absolute,./relative")
	f.Add("/abs/path", "./relative,/abs")
	f.Add("", "")
	f.Add("path", "")
	f.Add("path/to/file", "path")
	f.Add(".", ".")
	f.Add("..", "..")
	f.Add("../..", "../..")
	f.Add("./path/./to/./file", "./path")
	f.Add("path/./to/file", "path/.")
	f.Add("path/../to/file", "path/..")
	f.Add("path/to/link/../real", "path/to")
	f.Add("./path/to/../../other", "./path")
	f.Add("path/to/file/", "path/to/")
	f.Add("/path/to/file/", "/path/to/")
	f.Add("./path/to/file/", "./path/to/")

	f.Fuzz(func(t *testing.T, path, prefixesStr string) {
		var prefixes []string
		if prefixesStr != "" {
			prefixes = strings.Split(prefixesStr, ",")
		}

		result := TrimPrefixes(path, prefixes)

		if len(result) > len(path) {
			t.Fatalf("result %q is longer than input %q", result, path)
		}
	})
}

// FuzzMatchToString tests the matchToString function.
func FuzzMatchToString(f *testing.F) {
	f.Add("rule_name", "matched_string")
	f.Add("", "")
	f.Add("rule", "")
	f.Add("", "match")
	f.Add(strings.Repeat("a", 1000), strings.Repeat("b", 1000)) // long strings

	f.Fuzz(func(t *testing.T, ruleName, match string) {
		result := matchToString(ruleName, match)

		if len(result) > len(ruleName)+len(match)+100 {
			t.Fatalf("result length %d is unreasonably large", len(result))
		}
	})
}

// FuzzStringPoolIntern tests the StringPool.Intern function.
func FuzzStringPoolIntern(f *testing.F) {
	f.Add("hello")
	f.Add("")
	f.Add("test string with spaces")
	f.Add(strings.Repeat("a", 1000))
	f.Add("unicode: 你好世界")
	f.Add("emoji: 🎉🔥")
	f.Add("null\x00byte")
	f.Add("newline\nand\ttab")
	f.Add("special!@#$%^&*()")
	f.Add("\x00\x01\x02\x03")

	f.Fuzz(func(t *testing.T, input string) {
		pool := NewStringPool()

		s1 := pool.Intern(input)
		if s1 != input {
			t.Fatalf("intern(%q) returned %q", input, s1)
		}

		s2 := pool.Intern(input)
		if s2 != input {
			t.Fatalf("second Intern(%q) returned %q", input, s2)
		}

		if StringDataPointer(s1) != StringDataPointer(s2) {
			t.Fatal("interned strings should share the same backing data")
		}
	})
}

// FuzztStringPoolConcurrent tests general StringPool concurrency.
func FuzzStringPoolConcurrent(f *testing.F) {
	f.Add("test1,test2,test3")
	f.Add("a,a,a,a,a")
	f.Add("unique1,unique2,unique3,shared,shared")
	f.Add(strings.Repeat("x,", 50))
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		if input == "" {
			return
		}

		parts := strings.Split(input, ",")

		var filtered []string
		for _, p := range parts {
			if p != "" {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) == 0 {
			return
		}

		pool := NewStringPool()

		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		results := make([]map[string]uintptr, numGoroutines)

		for i := range numGoroutines {
			results[i] = make(map[string]uintptr)
			wg.Go(func() {
				defer wg.Done()
				for _, s := range filtered {
					// Create a copy to ensure unique backing array
					sCopy := string([]byte(s))
					interned := pool.Intern(sCopy)
					if interned != s {
						t.Errorf("intern returned wrong value: got %q, want %q", interned, s)
					}
					results[i][s] = StringDataPointer(interned)
				}
			})
		}

		wg.Wait()

		// Verify all goroutines got the same pointers for the same strings
		for _, s := range filtered {
			var firstPtr uintptr
			for i, res := range results {
				ptr := res[s]
				if i == 0 {
					firstPtr = ptr
				} else if ptr != firstPtr {
					t.Errorf("string %q has inconsistent pointers across goroutines", s)
				}
			}
		}
	})
}

// FuzzContainsUnprintable tests the containsUnprintable function.
func FuzzContainsUnprintable(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add([]byte{0x00})
	f.Add([]byte{0x1f})
	f.Add([]byte{0x20})
	f.Add([]byte{0x7e})
	f.Add([]byte{0x7f})
	f.Add([]byte{0x80})
	f.Add([]byte{0xff})
	f.Add([]byte("mixed\x00content"))

	f.Fuzz(func(t *testing.T, input []byte) {
		got := containsUnprintable(input)

		want := false
		for _, c := range input {
			if c < 32 || c > 126 {
				want = true
				break
			}
		}

		if got != want {
			t.Fatalf("containsUnprintable(%v) = %v, want %v", input, got, want)
		}
	})
}

// FuzzStringPoolAtomic ensures that pool.Intern is resistant to TOCTOU scenarios.
func FuzzStringPoolAtomic(f *testing.F) {
	f.Add("race-test")
	f.Add("another-test")
	f.Add("hello")
	f.Add("")
	f.Add("test string with spaces")
	f.Add(strings.Repeat("a", 1000))
	f.Add("unicode: 你好世界")
	f.Add("emoji: 🎉🔥")
	f.Add("null\x00byte")
	f.Add("newline\nand\ttab")
	f.Add("special!@#$%^&*()")
	f.Add("\x00\x01\x02\x03")
	f.Add(strings.Repeat("long", 100))

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1000 || input == "" {
			return
		}

		pool := NewStringPool()

		results := make(chan uintptr, numGoroutines)
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		start := make(chan struct{})

		for range numGoroutines {
			wg.Go(func() {
				defer wg.Done()
				<-start
				cpy := input
				interned := pool.Intern(cpy)
				results <- StringDataPointer(interned)
			})
		}

		close(start)
		wg.Wait()
		close(results)

		var firstPtr uintptr
		first := true
		for ptr := range results {
			if first {
				firstPtr = ptr
				first = false
			} else if ptr != firstPtr {
				t.Fatal("different pointers returned for same string")
			}
		}
	})
}

// FuzzReportLoad tests the Load function with random JSON inputs to find crashes,
// DoS via resource exhaustion, and unmarshaling bugs.
func FuzzReportLoad(f *testing.F) {
	// Seed with valid JSON reports
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Files":{}}`))
	f.Add([]byte(`{"Files":{"/bin/ls":{"Path":"/bin/ls","RiskScore":1,"RiskLevel":"low"}}}`))
	f.Add([]byte(`{"Files":{"/usr/bin/curl":{"Path":"/usr/bin/curl","RiskScore":2,"RiskLevel":"medium","Behaviors":{"net/http":{"Description":"HTTP"}}}}}`))

	// Malformed JSON
	f.Add([]byte(`{invalid json`))
	f.Add([]byte(`{"Files":`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	// Edge cases
	f.Add([]byte(`{"Files":null}`))
	f.Add([]byte(`[]`))       // Wrong type
	f.Add([]byte(`"string"`)) // Wrong type

	// Large JSON (potential DoS)
	largeReport := []byte(`{"Files":{`)
	for i := range 100 {
		if i > 0 {
			largeReport = append(largeReport, ',')
		}
		largeReport = append(largeReport, []byte(`"/file`+strings.Repeat("x", 100)+`":{"Path":"/file","RiskScore":1}`)...)
	}
	largeReport = append(largeReport, '}', '}')
	f.Add(largeReport)

	// Deeply nested JSON
	f.Add([]byte(`{"Files":{"/a":{"Behaviors":{"b1":{"Description":"d1"},"b2":{"Description":"d2"},"b3":{"Description":"d3"}}}}}`))

	// Special characters
	f.Add([]byte(`{"Files":{"/bin/\u0000":{"Path":"/bin/\u0000"}}}`))  // null byte
	f.Add([]byte(`{"Files":{"/bin/\n\r\t":{"Path":"/bin/\n\r\t"}}}`))  // whitespace
	f.Add([]byte(`{"Files":{"/bin/\"':{}\":{"Path":"/bin/\"':{}"}}}`)) // quote chars

	// Very long strings
	f.Add([]byte(`{"Files":{"/bin/` + strings.Repeat("a", 10000) + `":{"Path":"x"}}}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Load(data)
	})
}

// FuzzHandleOverrides tests the handleOverrides function with fuzzed inputs.
func FuzzHandleOverrides(f *testing.F) {
	f.Add("rule_a", 3, "override_x", 1, "rule_a", 1, false, false)
	f.Add("rule_a", 4, "override_x", 0, "rule_a", 0, true, true)
	f.Add("rule_a", 2, "override_x", 3, "nonexistent", 1, false, false)
	f.Add("", 0, "", 0, "", 0, false, false)

	f.Fuzz(func(t *testing.T, origName string, origRisk int, overName string, overRisk int, overTarget string, minScore int, scan, qir bool) {
		// Clamp values to valid ranges
		origRisk = max(origRisk%5, 0)
		overRisk = max(overRisk%5, 0)
		minScore = max(minScore%5, 0)

		if origName == "" || overName == "" {
			return
		}

		original := []*malcontent.Behavior{
			{RuleName: origName, RiskScore: origRisk, RiskLevel: RiskLevels[origRisk], ID: "id1"},
		}
		override := []*malcontent.Behavior{
			{RuleName: overName, RiskScore: overRisk, RiskLevel: RiskLevels[overRisk], Override: []string{overTarget}},
		}

		result := handleOverrides(original, override, minScore, scan, qir)

		// Result should never be longer than original
		if len(result) > len(original) {
			t.Errorf("result length %d exceeds original %d", len(result), len(original))
		}

		// Override rule itself should never appear in result
		for _, b := range result {
			if b.RuleName == overName {
				t.Errorf("override rule %q should not be in result", overName)
			}
		}

		// All remaining behaviors should meet the filter criteria
		for _, b := range result {
			if scan && qir && b.RiskScore < HIGH {
				t.Errorf("scan+QIR: behavior %q has score %d < HIGH", b.RuleName, b.RiskScore)
			}
			if !scan && b.RiskScore < minScore {
				t.Errorf("non-scan: behavior %q has score %d < minScore %d", b.RuleName, b.RiskScore, minScore)
			}
		}
	})
}

// FuzzGenerateKey tests the generateKey function with random namespace/rule inputs.
func FuzzGenerateKey(f *testing.F) {
	// Real YARA namespaces from the malcontent rule set
	f.Add("evasion/bypass_security/disable_firewall.yara", "disable_firewall")
	f.Add("crypto/aes/aes_key.yara", "aes_key")
	f.Add("3P/YARAForge/rule_name", "rule_name")
	f.Add("net/http/http_client.yara", "http_client")
	f.Add("exec/shell/bash_exec.yara", "bash_exec")
	f.Add("combo/mixed/multi_behavior.yara", "multi_behavior")
	f.Add("anti-static/obfuscation/packed.yara", "packed")
	f.Add("yara/JPCERT/Trojan_Linux_123", "Trojan_Linux_123")
	f.Add("yara/YARAForge/ELASTIC_Linux_Trojan_Gafgyt_E4A1982B", "ELASTIC_Linux_Trojan_Gafgyt_E4A1982B")
	f.Add("yara/elastic/rule", "rule")
	f.Add("single", "rule")
	f.Add("a/b", "b")
	f.Add("a/b/c.yara", "c")
	f.Add("a-b/c_d/e-f.yara", "e_f")
	f.Add("yara/.yara/", "foo")

	f.Fuzz(func(t *testing.T, src, rule string) {
		result := generateKey(src, rule)

		// Result should never contain ".yara"
		if strings.Contains(result, ".yara") {
			t.Errorf("generateKey(%q, %q) result %q contains .yara", src, rule, result)
		}

		// Result should never have a trailing "/"
		if result != "" && strings.HasSuffix(result, "/") {
			t.Errorf("generateKey(%q, %q) = %q has trailing slash", src, rule, result)
		}
	})
}

// FuzzThirdPartyKey tests the thirdPartyKey function with random path/rule inputs.
func FuzzThirdPartyKey(f *testing.F) {
	f.Add("yara/JPCERT/Trojan_Linux_123", "Trojan_Linux_123")
	f.Add("yara/YARAForge/ELASTIC_Linux_Trojan_Gafgyt_E4A1982B", "ELASTIC_Linux_Trojan_Gafgyt_E4A1982B")
	f.Add("yara/elastic/rule", "rule")
	f.Add("yara/bartblaze/APT_Example_Rule", "APT_Example_Rule")
	f.Add("yara/huntress/Trojan_Generic_ABC123", "Trojan_Generic_ABC123")
	f.Add("yara/signature-base/Linux_Malware_Detection", "Linux_Malware_Detection")
	f.Add("prefix/yara/JPCERT/rule_name", "rule_name")
	f.Add("yara/sub/deep/path", "deep")

	f.Fuzz(func(t *testing.T, path, rule string) {
		// thirdPartyKey requires "yara/" in the path to function
		if !strings.Contains(path, "yara/") {
			return
		}

		result := thirdPartyKey(path, rule)

		// Result should start with "3P/" or be empty
		if result != "" && !strings.HasPrefix(result, "3P/") {
			t.Errorf("thirdPartyKey(%q, %q) = %q does not start with 3P/", path, rule, result)
		}

		// If result is non-empty, check word count after source component
		if result != "" {
			parts := strings.SplitN(result, "/", 3)
			if len(parts) == 3 {
				ruleWords := strings.Split(parts[2], "_")
				if len(ruleWords) > 3 {
					t.Errorf("thirdPartyKey(%q, %q) = %q has more than 3 words in rule component: %v", path, rule, result, ruleWords)
				}
			}
		}
	})
}

// FuzzBehaviorRisk tests the behaviorRisk function with random inputs.
func FuzzBehaviorRisk(f *testing.F) {
	f.Add("evasion/bypass.yara", "rule_name", "high")
	f.Add("yara/JPCERT/rule", "rule", "")
	f.Add("combo/mixed", "test", "critical")
	f.Add("yara/YARAForge/ELASTIC_Linux_Trojan", "ELASTIC_Linux_Trojan", "low")
	f.Add("net/http/client.yara", "client", "medium")
	f.Add("yara/elastic/generic_rule", "generic_rule", "")
	f.Add("yara/huntress/keyword_tool", "keyword_tool", "")
	f.Add("exec/shell/bash", "bash", "harmless,critical")
	f.Add("", "", "")
	f.Add("yara/bartblaze/test", "test", "ignore")

	f.Fuzz(func(t *testing.T, ns, rule, tagStr string) {
		var tags []string
		if tagStr != "" {
			tags = strings.Split(tagStr, ",")
		}

		result := behaviorRisk(ns, rule, tags)

		// Result must always be in range [INVALID..CRITICAL] (-1..4)
		// INVALID (-1) is returned for tags like "ignore" and "none"
		if result < INVALID || result > CRITICAL {
			t.Errorf("behaviorRisk(%q, %q, %v) = %d, outside range [%d..%d]", ns, rule, tags, result, INVALID, CRITICAL)
		}

		// When tags contain a known level key, the tag value should win
		for _, tag := range tags {
			if expectedRisk, ok := Levels[tag]; ok {
				if result != expectedRisk {
					t.Errorf("behaviorRisk(%q, %q, %v) = %d, but tag %q should set risk to %d", ns, rule, tags, result, tag, expectedRisk)
				}
				break
			}
		}
	})
}

// FuzzUpgradeRisk tests the upgradeRisk function with random inputs.
func FuzzUpgradeRisk(f *testing.F) {
	f.Add(3, 2, int64(500))
	f.Add(3, 3, int64(1500000))
	f.Add(3, 7, int64(50000000))
	f.Add(2, 5, int64(100))
	f.Add(3, 0, int64(0))
	f.Add(3, 1, int64(512))
	f.Add(3, 10, int64(1024*1024*25))
	f.Add(0, 0, int64(0))
	f.Add(4, 100, int64(1))
	f.Add(1, 3, int64(1024))

	f.Fuzz(func(t *testing.T, riskScore, highCount int, size int64) {
		// Avoid negative sizes which don't make sense for file sizes
		if size < 0 {
			size = -size
		}

		riskCounts := map[int]int{HIGH: highCount}
		ctx := context.Background()

		result := upgradeRisk(ctx, riskScore, riskCounts, size)

		// upgradeRisk should never upgrade when riskScore != HIGH (3)
		if riskScore != HIGH && result {
			t.Errorf("upgradeRisk(ctx, %d, {HIGH: %d}, %d) = true, but riskScore != HIGH", riskScore, highCount, size)
		}

		// Result is a bool, so no panic means success for non-HIGH cases
		_ = result
	})
}
