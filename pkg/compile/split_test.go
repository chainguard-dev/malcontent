// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

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
	cached, err := filepath.Glob(filepath.Join(root, "malcontent", cachePrefix+splitVersion+"*"))
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
			if err := os.WriteFile(p, []byte("corrupt"), 0o600); err != nil {
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
