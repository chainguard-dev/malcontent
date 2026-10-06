// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"testing"
)

func TestSplitAndTrimCSV(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty input yields nil", "", nil},
		{"whitespace-only input yields nil", "  \t ", nil},
		{"separators without entries yield nil", " , ,, ", nil},
		{"single entry", "py_lib_alias_val", []string{"py_lib_alias_val"}},
		{"entries are trimmed and empty entries dropped", " a ,b,, c ", []string{"a", "b", "c"}},
		{"glob entries are kept verbatim", "py_lib_*,exfil?", []string{"py_lib_*", "exfil?"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := splitAndTrimCSV(tt.in)
			if (got == nil) != (tt.want == nil) || !slices.Equal(got, tt.want) {
				t.Errorf("splitAndTrimCSV(%q): got = %#v, want = %#v", tt.in, got, tt.want)
			}
		})
	}
}
