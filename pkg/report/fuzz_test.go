package report

import (
	"strings"
	"testing"
)

// FuzzLongestUnique tests the longestUnique function with random string inputs.
func FuzzLongestUnique(f *testing.F) {
	// Seed with test cases from the unit test
	f.Add("apple,banana,cherry,applecherry,bananaapple,cherrybanana")
	f.Add("test,testing,tester,testest")
	f.Add(",a,aa,aaa")
	f.Add("abc,def,ghi")
	f.Add("abc,abcabc,abcabcabc")

	// Add edge cases
	f.Add("")                                              // empty input
	f.Add("single")                                        // single string
	f.Add("a,a,a,a")                                       // all duplicates
	f.Add("very_long_string_" + strings.Repeat("x", 1000)) // long strings
	f.Add(strings.Repeat("a,", 100))                       // many strings
	f.Add("a,b,c,d,e,f,g,h,i,j,k,l,m")                     // many different strings

	f.Fuzz(func(t *testing.T, input string) {
		var strs []string
		if input != "" {
			strs = strings.Split(input, ",")
		}

		if len(strs) > 1000 {
			strs = strs[:1000]
		}

		for i, s := range strs {
			if len(s) > 10000 {
				strs[i] = s[:10000]
			}
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
	f.Add("./relative/path", "./relative")
	f.Add("/absolute/path", "/absolute,./relative")
	f.Add("", "")
	f.Add("path", "")
	f.Add("path/to/file", "path")
	f.Add("/path/to/file", "/path/to")

	f.Fuzz(func(t *testing.T, path, prefixesStr string) {
		var prefixes []string
		if prefixesStr != "" {
			prefixes = strings.Split(prefixesStr, ",")
		}

		if len(prefixes) > 100 {
			prefixes = prefixes[:100]
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
		if len(ruleName) > 10000 {
			ruleName = ruleName[:10000]
		}
		if len(match) > 10000 {
			match = match[:10000]
		}

		result := matchToString(ruleName, match)

		if len(result) > len(ruleName)+len(match)+100 {
			t.Fatalf("result length %d is unreasonably large", len(result))
		}
	})
}
