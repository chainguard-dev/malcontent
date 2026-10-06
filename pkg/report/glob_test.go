// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"regexp"
	"strings"
	"testing"
)

// globRegexp is the regular expression a path glob stands for, which glob
// must match exactly as.
func globRegexp(pattern string) *regexp.Regexp {
	parts := strings.Split(pattern, "*")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return regexp.MustCompile(`(?i)(?:^|/)` + strings.Join(parts, `.*`) + `$`)
}

func TestGlobMatchesItsRegexp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{name: "extension anywhere", pattern: "*.py", path: "a/b/c.py", want: true},
		{name: "extension in another case", pattern: "*.js", path: "src/Evil.JS", want: true},
		{name: "extension of a longer name", pattern: "*.py", path: "a/b/c.pyc", want: false},
		{name: "name after a directory", pattern: "*/setup.py", path: "pkg/setup.py", want: true},
		{name: "name with no directory", pattern: "*/setup.py", path: "setup.py", want: false},
		{name: "bare name in a directory", pattern: "setup.py", path: "x/y/setup.py", want: true},
		{name: "bare name at the start", pattern: "setup.py", path: "setup.py", want: true},
		{name: "bare name inside a longer name", pattern: "setup.py", path: "x/mysetup.py", want: false},
		{name: "directory prefix", pattern: "dist/*", path: "pkg/dist/x.js", want: true},
		{name: "directory prefix inside a name", pattern: "dist/*", path: "pkg/mydist/x.js", want: false},
		{name: "runs in order", pattern: "a*b*c", path: "x/aXbYc", want: true},
		{name: "runs out of order", pattern: "a*b*c", path: "x/aXcYb", want: false},
		{name: "first and last runs overlapping", pattern: "ab*ba", path: "aba", want: false},
		{name: "first and last runs meeting", pattern: "ab*ba", path: "abba", want: true},
		{name: "repeated middle run", pattern: "*b*b*", path: "abcb", want: true},
		{name: "star alone", pattern: "*", path: "anything/at/all", want: true},
		{name: "star alone on an empty path", pattern: "*", path: "", want: true},
		{name: "stars only", pattern: "**", path: "x", want: true},
		{name: "star does not span a newline", pattern: "*.py", path: "a\nb.py", want: false},
		{name: "start after a newline", pattern: "*.py", path: "a\n/b.py", want: true},
		{name: "star between runs does not span a newline", pattern: "a*.py", path: "x/a\nb.py", want: false},
		{name: "run holding a newline", pattern: "a\n*.py", path: "x/a\nb.py", want: true},
		{name: "Kelvin sign folds to k", pattern: "*.k", path: "x.\u212a", want: true},
		{name: "long s folds to s", pattern: "*.s", path: "x.\u017f", want: true},
		{name: "pattern letter folding to an ASCII letter", pattern: "*.\u212a", path: "x.K", want: true},
		{name: "case does not fold for punctuation", pattern: "*@", path: "x`", want: false},
		{name: "invalid byte in the path", pattern: "*.py", path: "\xff/a.py", want: true},
		{name: "invalid byte against a literal", pattern: "a*", path: "\xffa", want: false},
		{name: "empty path", pattern: "*.py", path: "", want: false},
		{name: "newline in a run covering the only newline between runs", pattern: "*\n*x", path: "a\nx", want: true},
		{name: "middle run only inside the last run", pattern: "x*ab*b", path: "xab", want: false},
		{name: "middle runs each need their own text", pattern: "a*bc*bc*d", path: "abcd", want: false},
		{name: "middle runs in order", pattern: "a*bc*bc*d", path: "abcXbcd", want: true},
		{name: "missing middle run", pattern: "a*zz*c", path: "abc", want: false},
		{name: "byte 0x80 is not U+0080 at the start", pattern: "\u0080*", path: "\x80x", want: false},
		{name: "byte 0x80 is not U+0080 at the end", pattern: "*\u0080", path: "x\x80", want: false},
		{name: "two invalid bytes are not U+0080", pattern: "*\u0080", path: "\xff\x80", want: false},
		{name: "first ASCII letter folds", pattern: "*a", path: "xA", want: true},
		{name: "last ASCII letter folds", pattern: "*z", path: "xZ", want: true},
		{name: "brackets do not fold to braces", pattern: "*[", path: "x{", want: false},
		{name: "trailing slash", pattern: "dist/*", path: "dist/", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if want := globRegexp(tt.pattern).MatchString(tt.path); want != tt.want {
				t.Fatalf("test case: regexp got = %t, want = %t", want, tt.want)
			}
			if got := compileGlob(tt.pattern).match(tt.path); got != tt.want {
				t.Errorf("match(%q, %q): got = %t, want = %t", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestCompileGlobsSkipsBlankEntries(t *testing.T) {
	t.Parallel()
	globs := compileGlobs(" *.py , ,*/setup.py,")
	if len(globs) != 2 {
		t.Fatalf("compileGlobs: got %d globs, want 2", len(globs))
	}
	if !matchesAny(globs, "pkg/setup.py") || !matchesAny(globs, "a.py") || matchesAny(globs, "a.js") {
		t.Errorf("matchesAny: got wrong matches for %v", globs)
	}
}
