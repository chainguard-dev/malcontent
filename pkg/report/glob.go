// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// glob is a compiled third-party path glob, such as a GuardDog path_include
// entry. '*' matches any run of characters other than a newline, path
// separators included, and the pattern is anchored to the end of the path and
// to its start or a '/' boundary: "*.py" matches "a/b/c.py", "*/setup.py"
// matches "pkg/setup.py", "setup.py" matches ".../setup.py" but not
// ".../mysetup.py", and "dist/*" matches ".../dist/x.js". Letters match under
// Unicode simple case folding, so "*.js" still matches "Evil.JS". These are
// the semantics of the regular expression (?i)(?:^|/)p0.*p1...pn$ for the
// literal runs p0...pn between the stars, which glob matches without
// backtracking.
type glob struct {
	// parts are the literal runs between the pattern's stars.
	parts []string
	// re matches a pattern whose literal runs hold a newline, which no star
	// may span.
	re *regexp.Regexp
}

// globCache memoizes compiled path globs keyed by their source pattern. The
// set of distinct path_include/path_exclude values across the rule corpus is
// small, so rules that are derived again share compiled globs.
var globCache sync.Map // map[string]*glob

// compileGlob compiles a single path glob, once.
func compileGlob(pattern string) *glob {
	if v, ok := globCache.Load(pattern); ok {
		g, _ := v.(*glob)
		return g
	}
	g := newGlob(pattern)
	globCache.Store(pattern, g)
	return g
}

// newGlob compiles a single path glob.
func newGlob(pattern string) *glob {
	g := &glob{parts: strings.Split(pattern, "*")}
	if strings.Contains(pattern, "\n") {
		parts := make([]string, len(g.parts))
		for i, part := range g.parts {
			parts[i] = regexp.QuoteMeta(part)
		}
		g.re = regexp.MustCompile(`(?i)(?:^|/)` + strings.Join(parts, `.*`) + `$`)
	}
	return g
}

// compileGlobs compiles each non-blank entry of a comma-separated path-glob
// list (third-party path_include/path_exclude syntax).
func compileGlobs(patterns string) []*glob {
	var res []*glob
	for p := range strings.SplitSeq(patterns, ",") {
		if p = strings.TrimSpace(p); p != "" {
			res = append(res, compileGlob(p))
		}
	}
	return res
}

// matchesAny reports whether path matches any of the compiled globs.
func matchesAny(globs []*glob, path string) bool {
	for _, g := range globs {
		if g.match(path) {
			return true
		}
	}
	return false
}

// match reports whether path matches g.
func (g *glob) match(path string) bool {
	if g.re != nil {
		return g.re.MatchString(path)
	}
	// The last run ends the path, which rejects most paths at once.
	if _, ok := foldSuffix(path, g.parts[len(g.parts)-1]); !ok {
		return false
	}
	for start := 0; ; {
		if g.matchAt(path[start:]) {
			return true
		}
		i := strings.IndexByte(path[start:], '/')
		if i < 0 {
			return false
		}
		start += i + 1
	}
}

// matchAt reports whether all of s matches the pattern's runs and stars.
func (g *glob) matchAt(s string) bool {
	rest, ok := cutFoldPrefix(s, g.parts[0])
	if !ok {
		return false
	}
	if len(g.parts) == 1 {
		return rest == ""
	}
	// No run holds a newline, so a newline between the first and last runs
	// falls under a star, which cannot match it.
	last := g.parts[len(g.parts)-1]
	end, ok := foldSuffix(rest, last)
	if !ok || strings.IndexByte(rest[:end], '\n') >= 0 {
		return false
	}
	// Taking the leftmost match of each middle run leaves the most text for
	// the runs after it.
	rest = rest[:end]
	for _, part := range g.parts[1 : len(g.parts)-1] {
		i, n := indexFold(rest, part)
		if i < 0 {
			return false
		}
		rest = rest[i+n:]
	}
	return true
}

// cutFoldPrefix returns s without its prefix that equals prefix under simple
// case folding.
func cutFoldPrefix(s, prefix string) (string, bool) {
	for prefix != "" {
		if s == "" {
			return "", false
		}
		r, n := decodeRune(prefix)
		c, m := decodeRune(s)
		if !foldEqual(r, c) {
			return "", false
		}
		prefix, s = prefix[n:], s[m:]
	}
	return s, true
}

// foldSuffix returns where the suffix of s that equals suffix under simple
// case folding starts.
func foldSuffix(s, suffix string) (int, bool) {
	end := len(s)
	for suffix != "" {
		if end == 0 {
			return 0, false
		}
		r, n := decodeLastRune(suffix)
		c, m := decodeLastRune(s[:end])
		if !foldEqual(r, c) {
			return 0, false
		}
		suffix, end = suffix[:len(suffix)-n], end-m
	}
	return end, true
}

// indexFold returns the index of the first substring of s that equals sub
// under simple case folding, and its length, or -1.
func indexFold(s, sub string) (int, int) {
	for i := 0; i <= len(s); {
		if rest, ok := cutFoldPrefix(s[i:], sub); ok {
			return i, len(s) - i - len(rest)
		}
		if i == len(s) {
			break
		}
		_, n := decodeRune(s[i:])
		i += n
	}
	return -1, 0
}

// decodeRune decodes the first rune of s as regular expressions read their
// input: an invalid byte is utf8.RuneError, one byte wide.
func decodeRune(s string) (rune, int) {
	if c := s[0]; c < utf8.RuneSelf {
		return rune(c), 1
	}
	return utf8.DecodeRuneInString(s)
}

// decodeLastRune decodes the last rune of s as decodeRune would.
func decodeLastRune(s string) (rune, int) {
	if c := s[len(s)-1]; c < utf8.RuneSelf {
		return rune(c), 1
	}
	return utf8.DecodeLastRuneInString(s)
}

// foldEqual reports whether c is r or in r's simple case folding orbit, which
// is when the case-insensitive literal r matches c.
func foldEqual(r, c rune) bool {
	if r == c {
		return true
	}
	if r < utf8.RuneSelf && c < utf8.RuneSelf {
		// ASCII letters differ from their other case only in bit 0x20.
		lower := r | 0x20
		return lower == c|0x20 && 'a' <= lower && lower <= 'z'
	}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f == c {
			return true
		}
	}
	return false
}
