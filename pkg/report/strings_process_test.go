// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"reflect"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
)

// reportMatchedRule scans data and returns the matching rule named name.
func reportMatchedRule(t *testing.T, rules *yarax.Rules, data []byte, name string) *yarax.Rule {
	t.Helper()
	for _, r := range scanBuf(t, rules, data).MatchingRules() {
		if r.Identifier() == name {
			return r
		}
	}
	t.Fatalf("rule %q did not match %q", name, data)
	return nil
}

func TestAppendMatchedStrings(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, map[string]string{
		"proc/text":    `rule proc_text { strings: $a = "hello" condition: $a }`,
		"proc/short":   `rule proc_short { strings: $b = "hiya" condition: $b }`,
		"proc/binary":  `rule proc_binary { strings: $h = { 01 02 03 } condition: $h }`,
		"proc/order":   `rule proc_order { strings: $a = "tail" $b = "head" condition: all of them }`,
		"proc/mixed":   `rule proc_mixed { strings: $h = { 01 02 03 } $t = "text" condition: any of them }`,
		"proc/partial": `rule proc_partial { strings: $h = { 01 02 03 } $t = "text" condition: $h or #t > 1 }`,
		"proc/regex":   `rule proc_regex { strings: $r = /ab[cd]/ condition: $r }`,
		"proc/single":  `rule proc_single { strings: $h = { 01 } condition: $h }`,
		"proc/overlap": `rule proc_overlap { strings: $r = /ab+c|b/ condition: $r }`,
	})
	// "hiya" matches at offset 8. The truncated views below cap their capacity
	// so an out-of-range match cannot be read from the spare backing array.
	short := []byte("xxxxxxxxhiya")
	// $a's match at offset 8 is processed before $b's match at offset 0.
	ordered := []byte("headxxxxtail")
	// The match at offset 0 runs to the end, past the truncated view, while
	// the later single-byte matches at offsets 1 to 4 lie within it.
	overlap := []byte("abbbbbbbbc")

	tests := []struct {
		name    string
		rule    string
		scanned []byte
		fc      []byte
		dst     []string
		want    []string
	}{
		{"match spanning all content", "proc_text", []byte("hello"), []byte("hello"), nil, []string{"hello"}},
		{"match ending at the last byte", "proc_text", []byte("xxhello"), []byte("xxhello"), nil, []string{"hello"}},
		{"match running past truncated content is dropped", "proc_short", short, short[:11:11], nil, nil},
		{"match starting past truncated content is dropped", "proc_short", short, short[:5:5], nil, nil},
		{"in-range match after a dropped match is kept", "proc_order", ordered, ordered[:6:6], nil, []string{"head"}},
		{"shorter match of the same pattern after a dropped match is kept", "proc_overlap", overlap, overlap[:5:5], nil, []string{"b", "b", "b", "b"}},
		{"single unprintable byte reports its pattern identifier", "proc_single", []byte{1}, []byte{1}, nil, []string{"$h"}},
		{"unprintable match reports its pattern identifier", "proc_binary", []byte{1, 2, 3}, []byte{1, 2, 3}, nil, []string{"$h"}},
		{"each unprintable match repeats the identifiers", "proc_binary", []byte{1, 2, 3, 0, 1, 2, 3}, []byte{1, 2, 3, 0, 1, 2, 3}, nil, []string{"$h", "$h"}},
		{"unprintable match reports every matched pattern", "proc_mixed", []byte("\x01\x02\x03 text"), []byte("\x01\x02\x03 text"), nil, []string{"$h", "$t", "text"}},
		{"patterns without matches are not reported", "proc_partial", []byte{1, 2, 3}, []byte{1, 2, 3}, nil, []string{"$h"}},
		{"repeated text is reported per match", "proc_text", []byte("hello hello hello"), []byte("hello hello hello"), nil, []string{"hello", "hello", "hello"}},
		{"differing matches of one pattern are each reported", "proc_regex", []byte("abc abd abc"), []byte("abc abd abc"), nil, []string{"abc", "abd", "abc"}},
		{"existing entries are kept", "proc_text", []byte("hello"), []byte("hello"), []string{"kept"}, []string{"kept", "hello"}},
		{"empty content adds nothing", "proc_text", []byte("hello"), nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := reportMatchedRule(t, rules, tt.scanned, tt.rule)
			if got := appendMatchedStrings(tt.dst, tt.fc, m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("appendMatchedStrings: got = %#v, want = %#v", got, tt.want)
			}
		})
	}
}

func TestAppendMatchedStringsNoMatches(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, map[string]string{
		"proc/text": `rule proc_text { strings: $a = "hello" condition: $a }`,
	}).Slice()
	if len(rules) != 1 {
		t.Fatalf("rules: got = %d, want = 1", len(rules))
	}
	if got := appendMatchedStrings(nil, []byte("abc"), rules[0]); got != nil {
		t.Errorf("appendMatchedStrings: got = %#v, want = nil", got)
	}
}
