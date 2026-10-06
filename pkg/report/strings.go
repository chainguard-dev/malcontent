// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"cmp"
	"index/suffixarray"
	"slices"
	"strings"

	yarax "github.com/VirusTotal/yara-x/go"
)

// maxLinearKeys bounds the number of distinct strings longestUnique compares
// pairwise. Larger sets use a suffix array, whose cost grows with the total
// length of the strings rather than with the square of their count.
const maxLinearKeys = 64

// appendMatchedStrings appends the text of each of m's matches that lies
// within fc to dst, in pattern order, and returns the extended slice. A match
// containing unprintable bytes contributes the identifiers of the rule's
// matched patterns instead. The appended strings are copies, so they stay
// valid after fc is released. yara-x does not expose the matched text, as
// rendering it would slow down scans that do not need it.
func appendMatchedStrings(dst []string, fc []byte, m *yarax.Rule) []string {
	fcl := uint64(len(fc))
	patterns := m.Patterns()

	// The pattern identifiers are the same for every unprintable match, so
	// they are collected on the first one.
	var ids []string
	haveIDs := false
	// A pattern often matches the same text many times, so an identical
	// match reuses the previous copy.
	prev := ""
	for i := range patterns {
		matches := patterns[i].Matches()
		for j := range matches {
			// Skip matches that do not lie within fc, which may be truncated.
			// Comparing o with the room before the match cannot overflow.
			o, l := matches[j].Offset(), matches[j].Length()
			if l > fcl || o > fcl-l {
				continue
			}
			b := fc[o : o+l]
			if string(b) == prev {
				dst = append(dst, prev)
				continue
			}
			if containsUnprintable(b) {
				if !haveIDs {
					ids, haveIDs = matchedPatternIDs(patterns), true
				}
				dst = append(dst, ids...)
				continue
			}
			prev = string(b)
			dst = append(dst, prev)
		}
	}
	return dst
}

// matchedPatternIDs returns the identifiers of the patterns that have a
// non-empty match, without adjacent repeats.
func matchedPatternIDs(patterns []yarax.Pattern) []string {
	ids := make([]string, 0, len(patterns))
	for i := range patterns {
		if slices.ContainsFunc(patterns[i].Matches(), func(m yarax.Match) bool {
			return m.Length() > 0
		}) {
			ids = append(ids, patterns[i].Identifier())
		}
	}
	return slices.Compact(ids)
}

// containsUnprintable reports whether b holds a byte outside printable ASCII.
func containsUnprintable[T ~string | ~[]byte](b T) bool {
	for i := range len(b) {
		if c := b[i]; c < 32 || c > 126 {
			return true
		}
	}
	return false
}

// matchToString renders one matched string of the rule named ruleName.
func matchToString(ruleName string, m string) string {
	if containsUnprintable(m) {
		return ruleName
	}

	switch {
	case strings.Contains(ruleName, "base64"),
		strings.Contains(ruleName, "xor"):
		// A single concatenation allocates the result once.
		return ruleName + "::" + m
	case strings.Contains(ruleName, "xml_key_val"):
		return strings.TrimSpace(strings.ReplaceAll(
			strings.ReplaceAll(m, "<key>", ""),
			"</key>", "",
		))
	}
	return strings.TrimSpace(m)
}

// matchStrings returns the match strings of a behavior of the rule named
// ruleName: each matched string rendered by matchToString, keeping only the
// longest distinct ones. It returns nil when ms is empty. It reorders and
// overwrites ms, and the result never shares ms's backing array.
func matchStrings(ruleName string, ms []string) []string {
	if len(ms) == 0 {
		return nil
	}

	// longestUnique depends only on the set of rendered strings, so each
	// distinct match is rendered once. Repeats are mostly adjacent, so
	// dropping those first leaves less to sort.
	ms = slices.Compact(ms)
	slices.Sort(ms)
	ms = slices.Compact(ms)

	raw := ms[:0]
	for _, m := range ms {
		if s := matchToString(ruleName, m); s != "" {
			raw = append(raw, s)
		}
	}
	return slices.Clone(longestUnique(raw))
}

// longestUnique returns the distinct non-empty strings of raw that do not
// occur inside another of them, longest first and then in lexical order. It
// reorders and overwrites raw, and the result may share raw's backing array.
func longestUnique(raw []string) []string {
	if len(raw) <= 1 {
		return raw
	}

	keys := raw[:0]
	nul := false
	for _, s := range raw {
		if s == "" {
			continue
		}
		nul = nul || strings.IndexByte(s, 0) >= 0
		keys = append(keys, s)
	}
	if len(keys) == 0 {
		return nil
	}

	slices.SortFunc(keys, longestFirst)
	keys = slices.Compact(keys)

	// The suffix array separates keys with the lowest byte value absent from
	// all of them. Without NUL in any key that separator is NUL, and the
	// suffix array finds exactly the substrings a pairwise search finds. When
	// every byte value occurs, matches may span a separator, so keys with NUL
	// always take the suffix array path to keep its results.
	if nul || len(keys) > maxLinearKeys {
		slices.Sort(keys)
		return longestUniqueSuffixArray(keys)
	}
	return longestUniqueLinear(keys)
}

// longestFirst orders strings by decreasing length, then lexically.
func longestFirst(a, b string) int {
	if c := cmp.Compare(len(b), len(a)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

// longestUniqueLinear drops each key that occurs inside a longer key. keys
// must be distinct, non-empty, and sorted by longestFirst. A key inside a
// longer key is also inside the longest key containing it, which is kept, so
// comparing against kept keys suffices. The result reuses keys' backing array
// and stays sorted by longestFirst.
func longestUniqueLinear(keys []string) []string {
	kept := keys[:0]
next:
	for _, k := range keys {
		for _, l := range kept {
			if strings.Contains(l, k) {
				continue next
			}
		}
		kept = append(kept, k)
	}
	return kept
}

// longestUniqueSuffixArray drops each key that a suffix array over all keys
// finds inside another key. keys must be distinct, non-empty, and sorted
// lexically. The result is sorted by longestFirst.
func longestUniqueSuffixArray(keys []string) []string {
	// Find a byte value not present in any string to use as separator
	sep := findSeparator(keys)

	totalLen := 0
	for _, s := range keys {
		totalLen += len(s) + 1
	}
	combined := make([]byte, 0, totalLen)
	offsets := make([]int, len(keys))
	for i, s := range keys {
		offsets[i] = len(combined)
		combined = append(combined, s...)
		combined = append(combined, sep)
	}

	sa := suffixarray.New(combined)

	// insideOther reports whether the occurrence at pos starts inside a key
	// other than keys[i], rather than inside keys[i] or on a separator.
	insideOther := func(i, pos int) bool {
		// The key holding pos is the last one that starts at or before it;
		// offsets[0] is 0, so there always is one.
		after, _ := slices.BinarySearch(offsets, pos+1)
		j := after - 1
		return j != i && pos < offsets[j]+len(keys[j])
	}

	longest := make([]string, 0, len(keys))
next:
	for i, k := range keys {
		for _, pos := range sa.Lookup([]byte(k), -1) {
			if insideOther(i, pos) {
				continue next
			}
		}
		longest = append(longest, k)
	}

	slices.SortFunc(longest, longestFirst)
	return longest
}

// findSeparator returns a byte value not present in any of the input strings.
func findSeparator(strs []string) byte {
	var used [256]bool
	for _, s := range strs {
		for _, b := range []byte(s) {
			used[b] = true
		}
	}
	for b := range used {
		if !used[b] {
			return byte(b)
		}
	}
	return 0
}
