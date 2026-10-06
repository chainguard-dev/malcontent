// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"reflect"
	"strconv"
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

func TestProcessMatchedStrings(t *testing.T) {
	t.Parallel()
	rules := compileTestRules(t, map[string]string{
		"proc/text":   `rule proc_text { strings: $a = "hello" condition: $a }`,
		"proc/short":  `rule proc_short { strings: $b = "hiya" condition: $b }`,
		"proc/binary": `rule proc_binary { strings: $h = { 01 02 03 } condition: $h }`,
		"proc/order":  `rule proc_order { strings: $a = "tail" $b = "head" condition: all of them }`,
	})
	// "hiya" matches at offset 8. The truncated views below cap their capacity
	// so an out-of-range match cannot be read from the spare backing array.
	short := []byte("xxxxxxxxhiya")
	// $a's match at offset 8 is processed before $b's match at offset 0.
	ordered := []byte("headxxxxtail")

	tests := []struct {
		name    string
		rule    string
		scanned []byte
		fc      []byte
		want    []string
	}{
		{"match spanning all content", "proc_text", []byte("hello"), []byte("hello"), []string{"hello"}},
		{"match ending at the last byte", "proc_text", []byte("xxhello"), []byte("xxhello"), []string{"hello"}},
		{"match running past truncated content is dropped", "proc_short", short, short[:11:11], []string{}},
		{"match starting past truncated content is dropped", "proc_short", short, short[:5:5], []string{}},
		{"in-range match after a dropped match is kept", "proc_order", ordered, ordered[:6:6], []string{"head"}},
		{"unprintable match reports its pattern identifier", "proc_binary", []byte{1, 2, 3}, []byte{1, 2, 3}, []string{"$h"}},
		{"empty content yields nil", "proc_text", []byte("hello"), nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := reportMatchedRule(t, rules, tt.scanned, tt.rule)
			if got := processMatchedStrings(tt.fc, m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("processMatchedStrings: got = %#v, want = %#v", got, tt.want)
			}
		})
	}
}

func TestMatchProcessorNoMatches(t *testing.T) {
	t.Parallel()
	if got := newMatchProcessor([]byte("abc"), nil, nil).process(); got != nil {
		t.Errorf("process: got = %#v, want = nil", got)
	}
}

// TestStringPoolResetsAtCap pins the reset to the entry that brings the
// distinct count to maxInternedStrings. An isolated pool keeps the count
// independent of other tests.
func TestStringPoolResetsAtCap(t *testing.T) {
	t.Parallel()
	pool := newIsolatedPool()
	for i := range maxInternedStrings - 1 {
		pool.Intern("cap-" + strconv.Itoa(i))
	}
	if got, want := pool.strings.Size(), maxInternedStrings-1; got != want {
		t.Fatalf("size below cap: got = %d, want = %d", got, want)
	}

	// Re-interning a stored value does not count toward the cap.
	pool.Intern("cap-0")
	if got, want := pool.strings.Size(), maxInternedStrings-1; got != want {
		t.Fatalf("size after repeat: got = %d, want = %d", got, want)
	}

	pool.Intern("cap-last")
	if got := pool.strings.Size(); got != 0 {
		t.Errorf("size after reaching cap: got = %d, want = 0", got)
	}
	if got := pool.count.Load(); got != 0 {
		t.Errorf("count after reaching cap: got = %d, want = 0", got)
	}
}
