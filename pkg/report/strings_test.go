// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// longestUniqueReference computes longestUnique through the suffix array
// alone, the path every input took before the pairwise search existed.
func longestUniqueReference(raw []string) []string {
	if len(raw) <= 1 {
		return raw
	}
	set := make(map[string]struct{}, len(raw))
	for _, s := range raw {
		if s != "" {
			set[s] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return longestUniqueSuffixArray(slices.Sorted(maps.Keys(set)))
}

// randomStrings returns n strings of up to maxLen bytes drawn from alphabet.
func randomStrings(rng *rand.Rand, alphabet string, n, maxLen int) []string {
	strs := make([]string, n)
	for i := range strs {
		b := make([]byte, rng.IntN(maxLen+1))
		for j := range b {
			b[j] = alphabet[rng.IntN(len(alphabet))]
		}
		strs[i] = string(b)
	}
	return strs
}

// TestContainsUnprintable tests the containsUnprintable function.
func TestContainsUnprintable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"empty", []byte{}, false},
		{"printable ASCII", []byte("hello world"), false},
		{"all printable", []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), false},
		{"printable symbols", []byte("!@#$%^&*()_+-=[]{}|;':\",./<>?"), false},
		{"space", []byte(" "), false},
		{"tilde", []byte("~"), false},
		{"null byte", []byte{0x00}, true},
		{"tab", []byte{0x09}, true},
		{"newline", []byte{0x0a}, true},
		{"carriage return", []byte{0x0d}, true},
		{"control char", []byte{0x1f}, true},
		{"DEL", []byte{0x7f}, true},
		{"high bit", []byte{0x80}, true},
		{"0xFF", []byte{0xff}, true},
		{"mixed printable and unprintable", []byte("hello\x00world"), true},
		{"boundary low", []byte{31}, true},   // just below printable
		{"boundary high", []byte{127}, true}, // just above printable
		{"exactly 32", []byte{32}, false},    // space is printable
		{"exactly 126", []byte{126}, false},  // tilde is printable
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := containsUnprintable(tt.input); got != tt.want {
				t.Errorf("containsUnprintable(%v): got = %v, want = %v", tt.input, got, tt.want)
			}
			if got := containsUnprintable(string(tt.input)); got != tt.want {
				t.Errorf("containsUnprintable(%q): got = %v, want = %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestMatchStringsResultIsIndependent verifies the result survives later
// writes to the input, which Generate reuses for the next rule.
func TestMatchStringsResultIsIndependent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ms   []string
		want []string
	}{
		{"single match", []string{"abc"}, []string{"abc"}},
		{"distinct matches", []string{"b", "a", "b"}, []string{"a", "b"}},
		{"contained match", []string{"curl", "curl -k"}, []string{"curl -k"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ms := slices.Clone(tt.ms)
			got := matchStrings("rule", ms)
			for i := range ms {
				ms[i] = "overwritten"
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("matchStrings(%q) after reuse of its input: got = %q, want = %q", tt.ms, got, tt.want)
			}
		})
	}
}

// TestLongestUniqueMatchesSuffixArray compares longestUnique with the suffix
// array result over random inputs whose small alphabets make many strings
// substrings of others. The sizes span both sides of maxLinearKeys, and NUL
// bytes exercise the separator fallback.
func TestLongestUniqueMatchesSuffixArray(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	alphabets := []string{"ab", "abc/._-", "\x00ab", "abcdefghijklmnopqrstuvwxyz0123456789 "}
	for i := range 2000 {
		raw := randomStrings(rng, alphabets[i%len(alphabets)], rng.IntN(2*maxLinearKeys+3), 12)
		want := longestUniqueReference(slices.Clone(raw))
		if got := longestUnique(slices.Clone(raw)); !reflect.DeepEqual(got, want) {
			t.Fatalf("longestUnique(%q): got = %q, want = %q", raw, got, want)
		}
	}
}

// TestLongestUniqueLinearMatchesSuffixArray compares the two containment
// searches directly on distinct NUL-free keys, including sets larger than
// longestUnique hands to the pairwise search.
func TestLongestUniqueLinearMatchesSuffixArray(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(3, 4))
	alphabets := []string{"ab", "abc", "abcdefgh/._"}
	for i := range 500 {
		set := map[string]struct{}{}
		for _, s := range randomStrings(rng, alphabets[i%len(alphabets)], rng.IntN(200)+1, 16) {
			if s != "" {
				set[s] = struct{}{}
			}
		}
		if len(set) == 0 {
			continue
		}
		lexical := slices.Sorted(maps.Keys(set))
		byLength := slices.SortedFunc(maps.Keys(set), longestFirst)
		want := longestUniqueSuffixArray(lexical)
		if got := longestUniqueLinear(byLength); !reflect.DeepEqual(got, want) {
			t.Fatalf("longestUniqueLinear(%q): got = %q, want = %q", lexical, got, want)
		}
	}
}

// benchmarkKeys returns n distinct strings shaped like matched text, 7 to 39
// bytes long, about a quarter of them substrings of the string before them.
func benchmarkKeys(n int) []string {
	rng := rand.New(rand.NewPCG(uint64(n), 7))
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789/._-"
	seen := make(map[string]struct{}, n)
	keys := make([]string, 0, n)
	for i := 0; len(keys) < n; i++ {
		s := randomStrings(rng, alphabet, 1, 32)[0] + "padding"
		if prev := len(keys) - 1; i%4 == 3 && prev >= 0 && len(keys[prev]) >= 8 {
			half := len(keys[prev]) / 2
			start := rng.IntN(half)
			s = keys[prev][start : start+half]
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		keys = append(keys, s)
	}
	return keys
}

// BenchmarkLongestUniquePaths compares the pairwise and suffix array
// containment searches at several set sizes, to place maxLinearKeys.
func BenchmarkLongestUniquePaths(b *testing.B) {
	for _, n := range []int{4, 16, 64, 128, 512} {
		keys := benchmarkKeys(n)
		byLength := slices.Clone(keys)
		slices.SortFunc(byLength, longestFirst)
		lexical := slices.Clone(keys)
		slices.Sort(lexical)
		buf := make([]string, n)

		b.Run(fmt.Sprintf("linear/%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				copy(buf, byLength)
				longestUniqueLinear(buf)
			}
		})
		b.Run(fmt.Sprintf("suffixarray/%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				copy(buf, lexical)
				longestUniqueSuffixArray(buf)
			}
		})
	}
}

// BenchmarkMatchStrings measures rendering a rule's matches when a few
// distinct strings repeat many times, as with a literal pattern in a large
// file.
func BenchmarkMatchStrings(b *testing.B) {
	distinct := benchmarkKeys(8)
	ms := make([]string, 1024)
	for i := range ms {
		ms[i] = distinct[i%len(distinct)]
	}
	buf := make([]string, len(ms))
	b.ReportAllocs()
	for b.Loop() {
		copy(buf, ms)
		matchStrings("rule", buf)
	}
}

func BenchmarkContainsUnprintableValid(b *testing.B) {
	data := []byte("This is a test string with only printable characters 1234567890")
	for b.Loop() {
		containsUnprintable(data)
	}
}

func BenchmarkContainsUnprintableInvalid(b *testing.B) {
	data := []byte("This has a null\x00byte")
	for b.Loop() {
		containsUnprintable(data)
	}
}

// BenchmarkContainsUnprintableString measures the string form matchToString
// uses, which must not copy its input.
func BenchmarkContainsUnprintableString(b *testing.B) {
	data := strings.Repeat("printable text ", 8)
	b.ReportAllocs()
	for b.Loop() {
		containsUnprintable(data)
	}
}
