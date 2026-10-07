// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	yarax "github.com/VirusTotal/yara-x/go"
)

// splitTestFS holds rules covering every reason a scoped rule stays
// universal, alongside rules that are set aside.
var splitTestFS = fstest.MapFS{
	"a/scripts.yara": {Data: []byte(`import "math"

rule js_only {
  meta:
    filetypes = "js,ts"
  strings:
    $a = "eval(atob("
  condition:
    $a and math.entropy(0, filesize) > 0
}

private rule helper {
  strings:
    $h = "helper-marker"
  condition:
    $h
}

rule py_uses_helper {
  meta:
    filetypes = "py"
  strings:
    $p = "exec(base64"
  condition:
    $p and helper
}

rule py_needed {
  meta:
    filetypes = "py"
  strings:
    $n = "needed-marker"
  condition:
    $n
}

rule universal_uses_scoped {
  strings:
    $u = "universal-marker"
  condition:
    $u and py_needed
}
`)},
	"b/binaries.yara": {Data: []byte("import \"elf\"\r\n\r\nrule elf_scoped {\r\n  meta:\r\n    filetypes = \"elf\"\r\n  condition:\r\n    elf.type == elf.ET_EXEC\r\n}\r\n\r\nrule path_scoped {\r\n  meta:\r\n    path_include = \"*.py,*/setup.py\"\r\n  strings:\r\n    $s = \"setup(\"\r\n  condition:\r\n    $s\r\n}\r\n\r\nprivate rule elf_exec {\r\n  condition:\r\n    elf.type == elf.ET_EXEC\r\n}\r\n\r\nrule elf_via_helper {\r\n  meta:\r\n    filetypes = \"elf\"\r\n  condition:\r\n    elf_exec\r\n}\r\n")},
	"e/gated.yara": {Data: []byte(`private rule mz_helper {
  strings:
    $h = "helper-gate"
  condition:
    $h
}

rule mz_gated {
  strings:
    $a = "mz-marker"
  condition:
    filesize < 1MB and uint16(0) == 0x5a4d and $a and mz_helper
}

rule elf_gated_be {
  meta:
    filetypes = "elf"
  strings:
    $e = "elf-marker"
  condition:
    (uint32be(0) == 0x7f454c46 and $e)
}

rule gated_or {
  strings:
    $o = "or-marker"
    $p = "or-other"
  condition:
    uint16(0) == 0x5a4d and $o or $p
}

rule gated_named {
  strings:
    $n = "named-marker"
  condition:
    uint16(0) == 0x5a4d and $n
}

rule names_gated {
  condition:
    gated_named
}
`)},
	"d/global.yara": {Data: []byte(`global rule small_files {
  condition:
    filesize < 1MB
}

rule scoped_under_global {
  meta:
    filetypes = "py"
  strings:
    $g = "global-marker"
  condition:
    $g
}
`)},
	"c/override.yara": {Data: []byte(`rule overridden {
  meta:
    filetypes = "sh"
  strings:
    $o = "overridden-marker"
  condition:
    $o
}

rule my_override : override {
  meta:
    description = "lowers overridden"
    overridden  = "low"
  strings:
    $m = "override-marker"
  condition:
    $m
}

rule malcontent {
  meta:
    filetypes = "macho"
  strings:
    $x = "malcontent-self"
  condition:
    $x
}

rule prefix_one {
  meta:
    filetypes = "rb"
  strings:
    $r = "prefix-one"
  condition:
    $r
}

rule prefix_user {
  strings:
    $w = "wildcard-marker"
  condition:
    $w and prefix_one
}
`)},
}

// headerKeys returns the headers of s.ByHeader, sorted.
func headerKeys(s *Split) []string {
	keys := make([]string, 0, len(s.ByHeader))
	for head := range s.ByHeader {
		keys = append(keys, string(head[:]))
	}
	slices.Sort(keys)
	return keys
}

func scopedNames(s *Split) []string {
	names := make([]string, 0, len(s.Scoped))
	for _, r := range s.Scoped {
		names = append(names, r.Key.Identifier)
	}
	return names
}

func TestRecursiveSplitSetsAsideOnlyIndependentScopedRules(t *testing.T) {
	t.Parallel()
	s, err := RecursiveSplit(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplit: %v", err)
	}
	// Universal rules keep: a scoped rule a universal rule names
	// (py_needed), an override target (overridden), the rule identifying
	// malcontent, a rule using a module that parses files (elf_scoped) or
	// naming a rule that does (elf_via_helper), a rule that another universal
	// rule names (prefix_one), and a rule sharing its file with a global rule
	// (scoped_under_global).
	if got, want := scopedNames(s), []string{"js_only", "py_uses_helper", "path_scoped"}; !slices.Equal(got, want) {
		t.Errorf("scoped rules: got = %v, want = %v", got, want)
	}
	if got := s.Scoped[2].Meta; !maps.Equal(got, map[string]string{"path_include": "*.py,*/setup.py"}) {
		t.Errorf("path_scoped meta: got = %v", got)
	}
}

func TestRecursiveSplitSetsAsideHeaderGatedRules(t *testing.T) {
	t.Parallel()
	s, err := RecursiveSplit(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplit: %v", err)
	}
	// Universal rules keep a rule whose header check is one side of an "or"
	// (gated_or) and a rule another universal rule names (gated_named). A
	// header-gated rule goes to its header's set even when its metadata
	// scopes it (elf_gated_be), with the rules it refers to (mz_helper).
	want := map[[2]byte][]string{
		{'M', 'Z'}:  {"mz_gated"},
		{0x7f, 'E'}: {"elf_gated_be"},
	}
	if len(s.ByHeader) != len(want) {
		t.Errorf("headers: got = %d, want = %d", len(s.ByHeader), len(want))
	}
	for head, names := range want {
		h, ok := s.ByHeader[head]
		if !ok {
			t.Errorf("header %q: got no rules, want %v", head, names)
			continue
		}
		rules, err := h.Load()
		if err != nil {
			t.Fatalf("Load %q: %v", head, err)
		}
		var got []string
		for _, r := range rules.Slice() {
			if id := r.Identifier(); id != "mz_helper" {
				got = append(got, id)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, names) {
			t.Errorf("header %q rules: got = %v, want = %v", head, got, names)
		}
	}
	mz, err := s.ByHeader[[2]byte{'M', 'Z'}].Load()
	if err != nil {
		t.Fatalf("Load MZ: %v", err)
	}
	if got := splitMatches(t, []byte("MZ mz-marker helper-gate"), mz); !slices.Equal(got, []string{"e/gated.yara:mz_gated"}) {
		t.Errorf("MZ rules with the helper's marker: got = %v, want mz_gated", got)
	}
	if got := splitMatches(t, []byte("MZ mz-marker"), mz); len(got) != 0 {
		t.Errorf("MZ rules without the helper's marker: got = %v, want none", got)
	}
	for _, r := range s.Universal.Slice() {
		if id := r.Identifier(); id == "mz_gated" || id == "elf_gated_be" {
			t.Errorf("universal rules: got %s, want it set aside", id)
		}
	}
	if slices.Contains(scopedNames(s), "elf_gated_be") {
		t.Errorf("scoped rules: got elf_gated_be, want it only in its header's set")
	}
}

func TestHeaderOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rule string
		want [2]byte
		ok   bool
	}{
		{name: "little-endian 16-bit check", rule: "rule a { condition: uint16(0) == 0x5a4d and $a }", want: [2]byte{'M', 'Z'}, ok: true},
		{name: "check after other conjuncts", rule: "rule a { condition: filesize < 2MB and #a > 2 and uint16(0) == 0x5A4D }", want: [2]byte{'M', 'Z'}, ok: true},
		{name: "big-endian 16-bit check", rule: "rule a { condition: uint16be(0) == 0x4d5a and $a }", want: [2]byte{'M', 'Z'}, ok: true},
		{name: "little-endian 32-bit check", rule: "rule a { condition: uint32(0) == 0x464c457f and $a }", want: [2]byte{0x7f, 'E'}, ok: true},
		{name: "big-endian 32-bit check", rule: "rule a { condition: uint32be(0) == 0x7f454c46 and $a }", want: [2]byte{0x7f, 'E'}, ok: true},
		{name: "decimal value and hex offset", rule: "rule a { condition: uint16(0x0) == 23117 and $a }", want: [2]byte{'M', 'Z'}, ok: true},
		{name: "whole condition in parentheses", rule: "rule a { condition: ((uint16(0) == 0x5a4d) and $a) }", want: [2]byte{'M', 'Z'}, ok: true},
		{name: "comments, strings, and regexes hold no operators", rule: "rule a {\n  meta:\n    d = \"x or condition: y\"\n  strings:\n    $r = /a or (b/\n  condition:\n    // or\n    uint16(0) == 0x5a4d /* or */ and $r and \"a or b\" matches /x or y/\n}", want: [2]byte{'M', 'Z'}, ok: true},
		{name: "check alone", rule: "rule a { condition: uint16(0) == 0x5a4d }", want: [2]byte{'M', 'Z'}, ok: true},
		{name: "escaped delimiters inside a string and a regex", rule: "rule a {\n  meta:\n    d = \"\\\" or condition: x\"\n  strings:\n    $r = /a\\/ or (/\n  condition:\n    uint16(0) == 0x5a4d and $r\n}", want: [2]byte{'M', 'Z'}, ok: true},
		{name: "parenthesized operands", rule: "rule a { condition: (uint16(0) == 0x5a4d) and ($a or $b) }", want: [2]byte{'M', 'Z'}, ok: true},
		{name: "parenthesized operands of a disjunction", rule: "rule a { condition: ($a and uint16(0) == 0x5a4d) or ($b) }", ok: false},
		{name: "top-level or", rule: "rule a { condition: uint16(0) == 0x5a4d and $a or $b }", ok: false},
		{name: "check inside a disjunction", rule: "rule a { condition: (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and $a }", ok: false},
		{name: "negated check", rule: "rule a { condition: not uint16(0) == 0x5a4d and $a }", ok: false},
		{name: "inequality", rule: "rule a { condition: uint16(0) != 0x5a4d and $a }", ok: false},
		{name: "nonzero offset", rule: "rule a { condition: uint16(2) == 0x5a4d and $a }", ok: false},
		{name: "computed offset", rule: "rule a { condition: uint32(uint32(0x3c)) == 0x4550 and $a }", ok: false},
		{name: "value wider than the read", rule: "rule a { condition: uint16(0) == 0x15a4d and $a }", ok: false},
		{name: "8-bit read", rule: "rule a { condition: uint8(0) == 0x4d and $a }", ok: false},
		{name: "check within an expression", rule: "rule a { condition: uint16(0) == 0x5a4d + 1 and $a }", ok: false},
		{name: "no condition", rule: "rule a { meta: d = \"uint16(0) == 0x5a4d\" }", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := headerOf(tt.rule)
			if ok != tt.ok || got != tt.want {
				t.Errorf("headerOf: got = %q, %t, want = %q, %t", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestRecursiveSplitPreservesOrderAndMatches(t *testing.T) {
	t.Parallel()
	full, err := Recursive(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("Recursive: %v", err)
	}
	s, err := RecursiveSplit(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplit: %v", err)
	}

	all := full.Slice()
	if len(s.Order) != len(all) {
		t.Fatalf("ordered rules: got = %d, want = %d", len(s.Order), len(all))
	}
	for i, r := range all {
		key := RuleKey{Namespace: r.Namespace(), Identifier: r.Identifier()}
		if got := s.Order[key]; got != i {
			t.Errorf("order of %v: got = %d, want = %d", key, got, i)
		}
	}

	indices := make([]int, len(s.Scoped))
	for i := range indices {
		indices[i] = i
	}
	scoped, err := s.CompileScoped(t.Context(), indices)
	if err != nil {
		t.Fatalf("CompileScoped: %v", err)
	}

	markers := " eval(atob( exec(base64 helper-marker needed-marker universal-marker setup( overridden-marker override-marker malcontent-self prefix-one wildcard-marker mz-marker helper-gate elf-marker or-marker named-marker global-marker"
	for _, head := range []string{"MZ", "\x7fELF", "#!", "M"} {
		data := []byte(head + markers)
		rs := []*yarax.Rules{s.Universal, scoped}
		if h, ok := s.ByHeader[[2]byte(data)]; ok {
			rules, err := h.Load()
			if err != nil {
				t.Fatalf("Load %q: %v", head, err)
			}
			rs = append(rs, rules)
		}
		if got, want := splitMatches(t, data, rs...), splitMatches(t, data, full); !slices.Equal(got, want) {
			t.Errorf("matches of %q: got = %v, want = %v", head, got, want)
		}
	}
}

// splitMatches returns the rules, of every rule set in rs, that match data.
func splitMatches(t *testing.T, data []byte, rs ...*yarax.Rules) []string {
	t.Helper()
	var out []string
	for _, r := range rs {
		res, err := yarax.NewScanner(r).Scan(data)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		for _, m := range res.MatchingRules() {
			out = append(out, m.Namespace()+":"+m.Identifier())
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestCompileScopedIncludesReferencedRules(t *testing.T) {
	t.Parallel()
	s, err := RecursiveSplit(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplit: %v", err)
	}
	i := slices.IndexFunc(s.Scoped, func(r ScopedRule) bool { return r.Key.Identifier == "py_uses_helper" })
	rules, err := s.CompileScoped(t.Context(), []int{i})
	if err != nil {
		t.Fatalf("CompileScoped: %v", err)
	}
	res, err := yarax.NewScanner(rules).Scan([]byte("exec(base64 helper-marker"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := make([]string, 0, len(res.MatchingRules()))
	for _, m := range res.MatchingRules() {
		got = append(got, m.Identifier())
	}
	// The private helper is compiled alongside but never reported.
	if want := []string{"py_uses_helper"}; !slices.Equal(got, want) {
		t.Errorf("matches: got = %v, want = %v", got, want)
	}
}

func TestParseSplitFile(t *testing.T) {
	t.Parallel()
	src := "import \"pe\"\r\nimport \"math\" // entropy\r\n\r\nrule a { condition: b and c_* }\r\nprivate rule b { condition: true }\r\nrule c_1 : tag { condition: true }\r\nrule c_2 { condition: $x or a }\r\n"
	f := parseSplitFile("ns.yara", []byte(src))
	if got, want := f.imports, []string{"pe", "math"}; !slices.Equal(got, want) {
		t.Errorf("imports: got = %v, want = %v", got, want)
	}
	names := make([]string, 0, len(f.rules))
	for _, r := range f.rules {
		names = append(names, r.name)
	}
	if want := []string{"a", "b", "c_1", "c_2"}; !slices.Equal(names, want) {
		t.Fatalf("rules: got = %v, want = %v", names, want)
	}
	tests := []struct {
		rule int
		want []int
	}{
		{rule: 0, want: []int{1, 2, 3}},
		{rule: 1, want: nil},
		{rule: 2, want: nil},
		// $x is a pattern, not a rule; a is a rule.
		{rule: 3, want: []int{0}},
	}
	for _, tt := range tests {
		if got := f.rules[tt.rule].refers; !slices.Equal(got, tt.want) {
			t.Errorf("refers of %s: got = %v, want = %v", f.rules[tt.rule].name, got, tt.want)
		}
	}
}

func TestScopeMeta(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		text string
		want map[string]string
	}{
		{name: "no scoping", text: "rule r { meta: description = \"x\" condition: true }", want: map[string]string{}},
		{name: "last repeated key counts", text: "rule r {\n meta:\n  filetypes = \"js\"\n  filetypes = \"py\"\n condition: true }", want: map[string]string{"filetypes": "py"}},
		{name: "escapes resolve", text: "rule r {\n meta:\n  path_include = \"a\\\\b,\\\"q\\\"\"\n condition: true }", want: map[string]string{"path_include": `a\b,"q"`}},
		{name: "keys after meta are ignored", text: "rule r {\n meta:\n  description = \"x\"\n strings:\n  $filetypes = \"filetypes\"\n condition: true }", want: map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := scopeMeta(tt.text); !maps.Equal(got, tt.want) {
				t.Errorf("scopeMeta: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestRecursiveSplitCached(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory.
	root := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", root)
	t.Setenv("HOME", root)

	first, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("first RecursiveSplitCached: %v", err)
	}
	cache := compileOpenRoot(t, filepath.Join(root, "malcontent"))
	cached, err := fs.Glob(cache.FS(), cachePrefix+splitVersion+"*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(cached) != 4 {
		t.Fatalf("cache files: got = %v, want rules, manifest, and their sidecars", cached)
	}

	second, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("second RecursiveSplitCached: %v", err)
	}
	if !maps.Equal(first.Order, second.Order) || !slices.Equal(scopedNames(first), scopedNames(second)) {
		t.Errorf("cached split: got order %v scoped %v, want order %v scoped %v", second.Order, scopedNames(second), first.Order, scopedNames(first))
	}
	if _, err := second.CompileScoped(t.Context(), []int{0, 1, 2}); err != nil {
		t.Errorf("CompileScoped after loading: %v", err)
	}
	if got, want := headerKeys(second), headerKeys(first); !slices.Equal(got, want) {
		t.Errorf("cached headers: got = %q, want = %q", got, want)
	}
	mz := []byte("MZ mz-marker helper-gate")
	for head, h := range second.ByHeader {
		rules, err := h.Load()
		if err != nil {
			t.Fatalf("Load %q after loading: %v", head, err)
		}
		if head == [2]byte(mz) {
			if got := splitMatches(t, mz, rules); !slices.Equal(got, []string{"e/gated.yara:mz_gated"}) {
				t.Errorf("cached MZ rules: got = %v, want mz_gated", got)
			}
		}
	}

	// A corrupt manifest is a cache miss; the split is rebuilt.
	for _, p := range cached {
		if strings.HasSuffix(p, ".manifest"+cacheSuffix) {
			if err := cache.WriteFile(p, []byte("corrupt"), 0o600); err != nil {
				t.Fatalf("corrupt manifest: %v", err)
			}
		}
	}
	third, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("third RecursiveSplitCached: %v", err)
	}
	if !maps.Equal(first.Order, third.Order) {
		t.Errorf("rebuilt split order: got = %v, want = %v", third.Order, first.Order)
	}
}

func TestCompileScopedCachesSets(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory.
	root := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", root)
	t.Setenv("HOME", root)
	indices := []int{0, 1, 2}
	data := []byte("eval(atob( exec(base64 helper-marker needed-marker")
	scopedCaches := func(cache *os.Root) []string {
		t.Helper()
		names, err := fs.Glob(cache.FS(), cachePrefix+splitVersion+"*.scoped-*")
		if err != nil {
			t.Fatalf("glob: %v", err)
		}
		return names
	}

	// A split compiled without the cache keeps nothing.
	plain, err := RecursiveSplit(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplit: %v", err)
	}
	fresh, err := plain.CompileScoped(t.Context(), indices)
	if err != nil {
		t.Fatalf("CompileScoped without the cache: %v", err)
	}
	want := splitMatches(t, data, fresh)

	first, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplitCached: %v", err)
	}
	cache := compileOpenRoot(t, filepath.Join(root, "malcontent"))
	if got, err := fs.Glob(cache.FS(), "*scoped*"); err != nil || len(got) != 0 {
		t.Fatalf("scoped caches before CompileScoped: got = (%v, %v), want none", got, err)
	}
	compiled, err := first.CompileScoped(t.Context(), indices)
	if err != nil {
		t.Fatalf("CompileScoped: %v", err)
	}
	if got := splitMatches(t, data, compiled); !slices.Equal(got, want) {
		t.Errorf("compiled matches: got = %v, want = %v", got, want)
	}
	names := scopedCaches(cache)
	if len(names) != 2 {
		t.Fatalf("scoped caches: got = %v, want the set and its sidecar", names)
	}
	name := slices.MinFunc(names, func(a, b string) int { return len(a) - len(b) })
	saved, err := cache.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}

	// A later run loads the set rather than compiling and saving it again.
	second, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("second RecursiveSplitCached: %v", err)
	}
	loaded, err := second.CompileScoped(t.Context(), indices)
	if err != nil {
		t.Fatalf("CompileScoped from the cache: %v", err)
	}
	if got := splitMatches(t, data, loaded); !slices.Equal(got, want) {
		t.Errorf("loaded matches: got = %v, want = %v", got, want)
	}
	if fi, err := cache.Stat(name); err != nil || !os.SameFile(fi, saved) {
		t.Errorf("scoped cache after loading: got = (%v, %v), want the saved file unchanged", fi, err)
	}

	// Loading a set marks it in use, so that pruning keeps it.
	aged := time.Now().Add(-cacheTouchInterval - time.Hour)
	if err := cache.Chtimes(name, aged, aged); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
	}
	if _, err := second.CompileScoped(t.Context(), indices); err != nil {
		t.Fatalf("CompileScoped from the cache: %v", err)
	}
	if fi, err := cache.Stat(name); err != nil || time.Since(fi.ModTime()) >= cacheTouchInterval {
		t.Errorf("scoped cache after loading it again: got = (%v, %v), want it marked in use", fi, err)
	}

	// A selection that fails to compile is an error, cached or not.
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, s := range []*Split{plain, second} {
		if rules, err := s.CompileScoped(canceled, []int{1}); err == nil {
			t.Errorf("CompileScoped with a canceled context: got = (%v, nil), want an error", rules)
		}
	}

	// A corrupt set is a cache miss: it is compiled and saved again.
	if err := cache.WriteFile(name, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt %s: %v", name, err)
	}
	rebuilt, err := second.CompileScoped(t.Context(), indices)
	if err != nil {
		t.Fatalf("CompileScoped after corruption: %v", err)
	}
	if got := splitMatches(t, data, rebuilt); !slices.Equal(got, want) {
		t.Errorf("rebuilt matches: got = %v, want = %v", got, want)
	}

	// Another selection has its own cache.
	if _, err := second.CompileScoped(t.Context(), []int{0}); err != nil {
		t.Fatalf("CompileScoped of another selection: %v", err)
	}
	if got := scopedCaches(cache); len(got) != 4 {
		t.Errorf("scoped caches for two selections: got = %v, want two sets and their sidecars", got)
	}
}

func TestCompileScopedWithoutAUsableCache(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory.
	cache := compileIsolateCache(t)
	s, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplitCached: %v", err)
	}
	data := []byte("eval(atob( exec(base64 helper-marker needed-marker")
	want, err := (&Split{files: s.files, Scoped: s.Scoped}).CompileScoped(t.Context(), []int{0, 1})
	if err != nil {
		t.Fatalf("CompileScoped without the cache: %v", err)
	}

	// A cache others can read is refused: the set is compiled and not saved.
	if err := cache.Chmod(".", 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = cache.Chmod(".", 0o700) })
	got, err := s.CompileScoped(t.Context(), []int{0, 1})
	if err != nil {
		t.Fatalf("CompileScoped with an unsafe cache: %v", err)
	}
	if g, w := splitMatches(t, data, got), splitMatches(t, data, want); !slices.Equal(g, w) {
		t.Errorf("matches: got = %v, want = %v", g, w)
	}
	if names, err := fs.Glob(cache.FS(), "*scoped*"); err != nil || len(names) != 0 {
		t.Errorf("scoped caches in an unsafe cache: got = (%v, %v), want none", names, err)
	}
}

func TestCompileScopedWarnsWhenItCannotSave(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory, and the log
	// functions are package variables.
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	cache := compileIsolateCache(t)
	s, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplitCached: %v", err)
	}
	if err := cache.Chmod(".", 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = cache.Chmod(".", 0o700) })
	logs := compileRecordLogs(t)
	if _, err := s.CompileScoped(t.Context(), []int{0}); err != nil {
		t.Fatalf("CompileScoped with a read-only cache: %v", err)
	}
	if !logs.has("WARN Failed to save scoped rules to cache") {
		t.Errorf("logs: got = %q, want a warning that the set was not saved", logs)
	}
}

func TestRecursiveSplitCachedPrunesAndRefreshesCaches(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory.
	cache := compileIsolateCache(t)
	old := time.Now().Add(-staleCacheThreshold - time.Hour)
	stale := func(name string) {
		t.Helper()
		if err := cache.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := cache.Chtimes(name, old, old); err != nil {
			t.Fatalf("chtimes %s: %v", name, err)
		}
	}
	gone := func(name, when string) {
		t.Helper()
		if _, err := cache.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stale %s %s: got err = %v, want it removed", name, when, err)
		}
	}

	// Compiling prunes caches no run has used for long.
	stale("rules-stale1.cache")
	if _, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS}); err != nil {
		t.Fatalf("RecursiveSplitCached: %v", err)
	}
	gone("rules-stale1.cache", "after compiling")
	names, err := fs.Glob(cache.FS(), cachePrefix+splitVersion+"*"+cacheSuffix)
	if err != nil || len(names) != 2 {
		t.Fatalf("split caches: got = (%v, %v), want the rules and the manifest", names, err)
	}

	// Loading prunes them too, and marks the split's own caches in use.
	stale("rules-stale2.cache")
	aged := time.Now().Add(-cacheTouchInterval - time.Hour)
	for _, name := range names {
		if err := cache.Chtimes(name, aged, aged); err != nil {
			t.Fatalf("chtimes %s: %v", name, err)
		}
	}
	if _, err := RecursiveSplitCached(t.Context(), []fs.FS{splitTestFS}); err != nil {
		t.Fatalf("second RecursiveSplitCached: %v", err)
	}
	gone("rules-stale2.cache", "after loading")
	for _, name := range names {
		if fi, err := cache.Stat(name); err != nil || time.Since(fi.ModTime()) >= cacheTouchInterval {
			t.Errorf("%s after loading: got = (%v, %v), want it marked in use", name, fi, err)
		}
	}
}

func TestSplitFromManifestRejectsOutOfRangeIndices(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		m    splitManifest
	}{
		{name: "scoped rule in a missing file", m: splitManifest{Scoped: []manifestScoped{{File: 1}}}},
		{name: "scoped rule past its file", m: splitManifest{Files: []manifestFile{{Rules: []manifestRule{{Name: "a"}}}}, Scoped: []manifestScoped{{Rule: 1}}}},
		{name: "reference outside its file", m: splitManifest{Files: []manifestFile{{Rules: []manifestRule{{Name: "a", Refers: []int{3}}}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := splitFromManifest(nil, tt.m); err == nil {
				t.Errorf("splitFromManifest: got nil error, want one")
			}
		})
	}
}

// BenchmarkCompileScoped compares compiling the scoped rules of the bundled
// rule set with loading them from the cache, as a later run does.
func BenchmarkCompileScoped(b *testing.B) {
	root := b.TempDir()
	b.Setenv("XDG_CACHE_HOME", root)
	b.Setenv("HOME", root)
	s, err := RecursiveSplitCached(b.Context(), getAllRuleFS())
	if err != nil {
		b.Fatalf("RecursiveSplitCached: %v", err)
	}
	indices := make([]int, 0, len(s.Scoped))
	for i := range s.Scoped {
		if i%4 == 0 {
			indices = append(indices, i)
		}
	}
	// Fill the cache, as an earlier run would.
	if _, err := s.CompileScoped(b.Context(), indices); err != nil {
		b.Fatalf("CompileScoped: %v", err)
	}
	uncached := *s
	uncached.cacheName = ""
	for _, tt := range []struct {
		name  string
		split *Split
	}{{name: "compile", split: &uncached}, {name: "cached", split: s}} {
		b.Run(tt.name, func(b *testing.B) {
			for b.Loop() {
				rules, err := tt.split.CompileScoped(b.Context(), indices)
				if err != nil {
					b.Fatalf("CompileScoped: %v", err)
				}
				rules.Destroy()
			}
		})
	}
}

func TestSaveVerifiedCleansUp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		blocked   string // created as a directory so that renaming onto it fails
		wantErr   string
		wantSaved bool
	}{
		{name: "saved", wantSaved: true},
		{name: "path taken by a directory", blocked: "data.cache", wantErr: "rename cache file"},
		{name: "sidecar path taken by a directory", blocked: "data.cache" + sidecarSuffix, wantErr: "rename sidecar file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cache := compileOpenRoot(t, t.TempDir())
			if tt.blocked != "" {
				if err := cache.Mkdir(tt.blocked, 0o700); err != nil {
					t.Fatalf("mkdir %s: %v", tt.blocked, err)
				}
			}
			err := saveVerified(cache, "data.cache", []byte("data"))
			if (err == nil) != (tt.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("saveVerified: got err = %v, want one containing %q", err, tt.wantErr)
			}
			if leftovers, err := fs.Glob(cache.FS(), ".rules-*.tmp"); err != nil || len(leftovers) != 0 {
				t.Errorf("temp files left behind: got = (%v, %v), want none", leftovers, err)
			}
			got, err := loadVerified(cache, "data.cache")
			if saved := err == nil && string(got) == "data"; saved != tt.wantSaved {
				t.Errorf("loadVerified after saving: got = (%q, %v), want saved = %v", got, err, tt.wantSaved)
			}
			if fi, err := cache.Lstat("data.cache"); tt.blocked == "data.cache"+sidecarSuffix && err == nil && fi.Mode().IsRegular() {
				t.Error("data without its sidecar: got it left behind, want it removed")
			}
		})
	}
}

func TestLoadVerifiedRejectsDataThatDoesNotMatchItsDigest(t *testing.T) {
	t.Parallel()
	cache := compileOpenRoot(t, t.TempDir())
	if err := saveVerified(cache, "data.cache", []byte("data")); err != nil {
		t.Fatalf("saveVerified: %v", err)
	}
	// Well-formed data saved under another name, swapped in without its
	// sidecar.
	if err := cache.WriteFile("data.cache", []byte("other"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, err := loadVerified(cache, "data.cache"); err == nil {
		t.Errorf("loadVerified of swapped data: got = (%q, nil), want an error", got)
	}
}
