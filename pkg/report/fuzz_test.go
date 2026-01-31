package report

import (
	"strings"
	"sync"
	"testing"
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
		if len(input) > 10000 {
			input = input[:10000]
		}

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
		if len(parts) > 100 {
			parts = parts[:100]
		}

		var filtered []string
		for _, p := range parts {
			if len(p) <= 1000 && p != "" {
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
		if len(input) > 10000 {
			input = input[:10000]
		}

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
