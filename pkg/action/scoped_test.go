// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/minio/sha256-simd"

	yarax "github.com/VirusTotal/yara-x/go"
)

// scopedTestFS holds rules whose reports depend on how scoped and universal
// matches interleave: rules sharing a behavior ID with equal risk (the first
// declared wins), an override of a universal rule, path-scoped rules, and a
// scoped rule that relies on a private rule.
var scopedTestFS = fstest.MapFS{
	"exec/shell/a.yara": {Data: []byte(`rule shell_scoped: medium {
  meta:
    description = "scoped shell rule"
    filetypes   = "sh,bash"
  strings:
    $a = "curl -fsSL"
  condition:
    $a
}

rule shell_universal: medium {
  meta:
    description = "universal shell rule with a longer description"
  strings:
    $a = "curl -fsSL"
  condition:
    $a
}
`)},
	"exec/shell/b.yara": {Data: []byte(`rule shell_universal_b: high {
  meta:
    description = "second universal rule"
  strings:
    $a = "| sh"
  condition:
    $a
}
`)},
	"anti-static/obfuscation/js.yara": {Data: []byte(`rule js_eval: high {
  meta:
    description = "evaluates decoded text"
    filetypes   = "js,ts"
  strings:
    $a = "eval(atob("
  condition:
    $a
}

private rule js_marker {
  strings:
    $m = "fromCharCode"
  condition:
    $m
}

rule js_charcode: medium {
  meta:
    filetypes = "js"
  strings:
    $a = "String."
  condition:
    $a and js_marker
}
`)},
	"exec/shell/mz.yara": {Data: []byte(`rule mz_shell: high {
  meta:
    description = "PE that runs a shell"
  strings:
    $a = "cmd.exe /c"
  condition:
    filesize < 1MB and uint16(0) == 0x5a4d and $a
}

rule mz_shell_scoped: medium {
  meta:
    description = "PE scoped to executables that runs a shell"
    filetypes   = "exe"
  strings:
    $a = "cmd.exe /c"
  condition:
    uint16(0) == 0x5a4d and $a
}
`)},
	"net/download/py.yara": {Data: []byte(`rule py_urlopen: medium {
  meta:
    path_include = "*.py,*/setup.py"
  strings:
    $a = "urlopen("
  condition:
    $a
}

rule py_lower: override {
  meta:
    description = "lowers the universal rule"
    py_universal = "low"
  strings:
    $a = "urlopen("
  condition:
    $a
}

rule py_universal: high {
  strings:
    $a = "urlopen("
  condition:
    $a
}
`)},
}

func TestScopedScanMatchesFullScan(t *testing.T) {
	t.Parallel()
	fss := []fs.FS{scopedTestFS}
	full, err := compile.Recursive(t.Context(), fss)
	if err != nil {
		t.Fatalf("Recursive: %v", err)
	}
	split, err := compile.RecursiveSplit(t.Context(), fss)
	if err != nil {
		t.Fatalf("RecursiveSplit: %v", err)
	}
	if len(split.Scoped) == 0 {
		t.Fatal("fixture precondition: got no scoped rules, want some")
	}
	registerSplit(split)

	dir := t.TempDir()
	files := []struct {
		name string
		data string
	}{
		{name: "install.sh", data: "#!/bin/sh\ncurl -fsSL https://example.com/x | sh\n"},
		{name: "install", data: "#!/bin/sh\ncurl -fsSL https://example.com/x | sh\n"},
		{name: "app.js", data: "var s = String.fromCharCode(72); eval(atob('aGk='));\n"},
		{name: "app.py", data: "import urllib\nurllib.request.urlopen('https://example.com')\n"},
		{name: filepath.Join("pkg", "setup.py"), data: "import urllib\nurllib.request.urlopen('https://example.com')\n"},
		{name: "main.go", data: "package main\n// eval(atob( curl -fsSL urlopen(\nfunc main() {}\n"},
		{name: "tool.exe", data: "MZ\x90\x00 cmd.exe /c curl -fsSL | sh\n"},
		{name: "notes.txt", data: "run cmd.exe /c here\n"},
		{name: "m", data: "M"},
	}
	for _, f := range files {
		path := scanTestWriteFile(t, filepath.Join(dir, f.name), []byte(f.data))
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			for _, scan := range []bool{false, true} {
				want, err := scanSinglePath(t.Context(), malcontent.Config{Rules: full, Scan: scan, IncludeDataFiles: true}, path, fss, path, "", nil)
				if err != nil {
					t.Fatalf("full scan: %v", err)
				}
				got, err := scanSinglePath(t.Context(), malcontent.Config{Rules: split.Universal, Scan: scan, IncludeDataFiles: true}, path, fss, path, "", nil)
				if err != nil {
					t.Fatalf("scoped scan: %v", err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("scan=%t report:\ngot  = %+v\nwant = %+v", scan, got, want)
				}
			}
		})
	}
}

func TestScopedRulesForHeader(t *testing.T) {
	t.Parallel()
	split, err := compile.RecursiveSplit(t.Context(), []fs.FS{scopedTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplit: %v", err)
	}
	sr := newScopedRules(split)
	tests := []struct {
		name  string
		fc    []byte
		known bool
		want  int
	}{
		{name: "a PE file gets the rules for its header", fc: []byte("MZ\x90\x00"), known: true, want: 1},
		{name: "a file of just the header gets the rules for it", fc: []byte("MZ"), known: true, want: 1},
		{name: "a file with another header gets none", fc: []byte("#!/bin/sh"), known: true, want: 0},
		{name: "a file shorter than a header gets none", fc: []byte("M"), known: true, want: 0},
		{name: "an empty file gets none", fc: nil, known: true, want: 0},
		{name: "unknown contents get every header's rules", fc: nil, known: false, want: len(split.ByHeader)},
	}
	if len(split.ByHeader) == 0 {
		t.Fatal("fixture precondition: got no rules by header, want some")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sets, err := sr.forHeader(tt.fc, tt.known)
			if err != nil {
				t.Fatalf("forHeader: %v", err)
			}
			if len(sets) != tt.want {
				t.Errorf("forHeader: got %d rule sets, want %d", len(sets), tt.want)
			}
			for _, rules := range sets {
				if _, ok := scopedSets.Load(rules); !ok {
					t.Errorf("forHeader: rule set has no scanners kept for it")
				}
			}
		})
	}
}

func TestScopedRulesForHeaderLoadFailure(t *testing.T) {
	t.Parallel()
	// A header rule set without serialized rules fails to load.
	sr := newScopedRules(&compile.Split{ByHeader: map[[2]byte]*compile.HeaderRules{{'M', 'Z'}: {}}})
	tests := []struct {
		name  string
		fc    []byte
		known bool
	}{
		{name: "a file with the header reports the failure", fc: []byte("MZ\x90\x00"), known: true},
		{name: "unknown contents report the failure", known: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sets, err := sr.forHeader(tt.fc, tt.known)
			if err == nil {
				t.Errorf("forHeader error: got nil, want the load failure")
			}
			if sets != nil {
				t.Errorf("forHeader: got %d rule sets, want none", len(sets))
			}
		})
	}
}

func TestNewScopedRulesSharesScopes(t *testing.T) {
	t.Parallel()
	rule := func(id string, meta map[string]string) compile.ScopedRule {
		return compile.ScopedRule{Key: compile.RuleKey{Namespace: "exec/shell/a.yara", Identifier: id}, Meta: meta}
	}
	sh := map[string]string{"filetypes": "sh"}
	py := map[string]string{"filetypes": "py"}
	shAgain := map[string]string{"filetypes": "sh"}
	sr := newScopedRules(&compile.Split{Scoped: []compile.ScopedRule{
		rule("a", sh), rule("b", py), rule("c", shAgain), rule("d", sh),
	}})
	if got, want := len(sr.scopes), 2; got != want {
		t.Errorf("distinct scopes: got = %d, want = %d", got, want)
	}
	if want := []int{0, 1, 0, 0}; !slices.Equal(sr.ruleScope, want) {
		t.Errorf("rule scopes: got = %v, want = %v", sr.ruleScope, want)
	}
}

func TestScopeKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		a, b      map[string]string
		wantEqual bool
	}{
		{
			name:      "identical scoping metadata shares a key",
			a:         map[string]string{"filetypes": "sh", "path_include": "*.sh"},
			b:         map[string]string{"filetypes": "sh", "path_include": "*.sh"},
			wantEqual: true,
		},
		{
			name:      "metadata other than scoping keys is ignored",
			a:         map[string]string{"filetypes": "sh", "description": "runs a shell"},
			b:         map[string]string{"filetypes": "sh"},
			wantEqual: true,
		},
		{
			name: "different filetypes differ",
			a:    map[string]string{"filetypes": "sh"},
			b:    map[string]string{"filetypes": "py"},
		},
		{
			name: "the same value under different keys differs",
			a:    map[string]string{"path_include": "*.py"},
			b:    map[string]string{"path_exclude": "*.py"},
		},
		{
			name: "values that would run together differ",
			a:    map[string]string{"filetypes": "x", "path_include": "y"},
			b:    map[string]string{"filetypes": "xpath_include=y"},
		},
		{
			name: "an absent key differs from an empty value",
			a:    map[string]string{},
			b:    map[string]string{"filetypes": ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := scopeKey(tt.a) == scopeKey(tt.b); got != tt.wantEqual {
				t.Errorf("keys equal: got = %t (%q, %q), want = %t", got, scopeKey(tt.a), scopeKey(tt.b), tt.wantEqual)
			}
		})
	}
}

func TestMergeMatchesListsEachRuleOnce(t *testing.T) {
	t.Parallel()
	yrs, _ := scanTestRules(t)
	npm := readTestFile(t, scanTestNPMFixture)
	hit, err := scanBytes(yrs, npm, sha256.Sum256(npm))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	none, err := scanBytes(yrs, []byte("zz"), sha256.Sum256([]byte("zz")))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	keys := func(rules []*yarax.Rule) []compile.RuleKey {
		out := make([]compile.RuleKey, 0, len(rules))
		for _, r := range rules {
			out = append(out, compile.RuleKey{Namespace: r.Namespace(), Identifier: r.Identifier()})
		}
		return out
	}
	want := keys(hit.MatchingRules())
	if len(want) == 0 || len(none.MatchingRules()) != 0 {
		t.Fatalf("fixture precondition: got %d and %d matching rules, want some and none", len(want), len(none.MatchingRules()))
	}

	tests := []struct {
		name   string
		u      *yarax.ScanResults
		others []*yarax.ScanResults
	}{
		{name: "universal matches alone are listed in order", u: hit},
		{name: "matches repeated by another scan are listed once", u: hit, others: []*yarax.ScanResults{hit}},
		{name: "matches repeated across other scans are listed once", u: none, others: []*yarax.ScanResults{hit, hit}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := keys(mergeMatches(tt.u, tt.others...)); !slices.Equal(got, want) {
				t.Errorf("merged rules: got = %v, want = %v", got, want)
			}
		})
	}
}

func TestScopedRulesApplicable(t *testing.T) {
	t.Parallel()
	split, err := compile.RecursiveSplit(t.Context(), []fs.FS{scopedTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplit: %v", err)
	}
	sr := newScopedRules(split)
	names := func(indices []int) []string {
		out := make([]string, 0, len(indices))
		for _, i := range indices {
			out = append(out, split.Scoped[i].Key.Identifier)
		}
		slices.Sort(out)
		return out
	}

	tests := []struct {
		name string
		path string
		ext  string
		want []string
	}{
		{name: "javascript gets the js rules", path: "/src/app.js", ext: "js", want: []string{"js_charcode", "js_eval"}},
		{name: "typescript gets only the rule scoped to ts", path: "/src/app.ts", ext: "ts", want: []string{"js_eval"}},
		{name: "a python path gets the path-scoped rule", path: "/src/app.py", ext: "py", want: []string{"py_urlopen"}},
		{name: "setup.py anywhere gets the path-scoped rule", path: "/src/pkg/setup.py", ext: "", want: []string{"js_charcode", "js_eval", "py_urlopen", "shell_scoped"}},
		{name: "an ELF binary gets no scoped rules", path: "/bin/tool", ext: "elf", want: nil},
		{name: "an undetected type gets every filetype-scoped rule", path: "/data/blob", ext: "", want: []string{"js_charcode", "js_eval", "shell_scoped"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var kind *programkind.FileType
			if tt.ext != "" {
				kind = &programkind.FileType{Ext: tt.ext}
			}
			key, indices := sr.applicable(kind, tt.path, "", malcontent.Config{})
			if got := names(indices); !slices.Equal(got, tt.want) {
				t.Errorf("applicable: got = %v, want = %v", got, tt.want)
			}
			key2, _ := sr.applicable(kind, tt.path, "", malcontent.Config{})
			if key != key2 {
				t.Errorf("key: got %q then %q, want a stable key", key, key2)
			}
		})
	}
}

func TestScanFileReportsHeaderLoadFailure(t *testing.T) {
	t.Parallel()
	// A rule set divided by scope whose rules for PE files fail to load.
	universal := scanTestMarkerRules(t)
	registerSplit(&compile.Split{Universal: universal, ByHeader: map[[2]byte]*compile.HeaderRules{{'M', 'Z'}: {}}})
	fc := []byte("MZ\x90\x00 scan-test-marker")
	path := scanTestWriteFile(t, filepath.Join(t.TempDir(), "tool.exe"), fc)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	s := sniffFile(t.Context(), path, fi)
	defer s.close()

	matching, err := scanFile(t.Context(), malcontent.Config{Rules: universal}, s, path, "", s.content.Bytes(), sha256.Sum256(fc))
	if err == nil {
		t.Errorf("scanFile error: got = nil, want the header rule set's load failure")
	}
	if matching != nil {
		t.Errorf("matching rules: got %d, want none", len(matching))
	}
}

func TestScanFileReportsScopedScanFailure(t *testing.T) {
	// Not parallel: replaces scanBytes.
	split, err := compile.RecursiveSplit(t.Context(), []fs.FS{scopedTestFS})
	if err != nil {
		t.Fatalf("RecursiveSplit: %v", err)
	}
	registerSplit(split)
	errScan := errors.New("scan failed")
	// The universal scan succeeds; the scan with the rules for PE files fails.
	calls := countScans(t, func(call int64) error {
		if call == 2 {
			return errScan
		}
		return nil
	})
	fc := []byte("MZ\x90\x00 cmd.exe /c curl -fsSL | sh\n")
	path := scanTestWriteFile(t, filepath.Join(t.TempDir(), "tool.exe"), fc)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	s := sniffFile(t.Context(), path, fi)
	defer s.close()

	matching, err := scanFile(t.Context(), malcontent.Config{Rules: split.Universal}, s, path, "", s.content.Bytes(), sha256.Sum256(fc))
	if !errors.Is(err, errScan) {
		t.Errorf("scanFile error: got = %v, want = %v", err, errScan)
	}
	if matching != nil {
		t.Errorf("matching rules: got %d, want none", len(matching))
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("scans: got = %d, want = 2", n)
	}
}
