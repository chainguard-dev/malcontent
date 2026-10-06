// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

func TestScopeAppliesMatchesRuleScope(t *testing.T) {
	t.Parallel()
	metas := []map[string]string{
		{},
		{"filetypes": "js,ts"},
		{"filetypes": "py"},
		{"filetypes": "jar,java"},
		{"path_include": "*.py,*/setup.py"},
		{"path_include": "*.go", "path_exclude": "vendor/*"},
		{"filetypes": "sh", "path_exclude": "*/test/*"},
	}
	targets := []struct {
		ext, path, expath string
		c                 malcontent.Config
	}{
		{ext: "js", path: "/src/app.js"},
		{ext: "py", path: "/src/pkg/setup.py"},
		{ext: "", path: "/data/blob"},
		{ext: "class", path: "/x/A.class"},
		{ext: "go", path: "/src/vendor/x/y.go"},
		{ext: "sh", path: "/repo/test/run.sh"},
		{ext: "py", path: "/img/root/app/main.py", expath: "/img/root", c: malcontent.Config{OCI: true}},
		{ext: "elf", path: "/tmp/scan/bin/tool", c: malcontent.Config{TrimPrefixes: []string{"/tmp/scan"}}},
		{ext: "py", path: "", expath: ""},
	}
	for i, meta := range metas {
		src := "rule r {\n  meta:\n"
		for _, k := range []string{"filetypes", "path_include", "path_exclude"} {
			if v, ok := meta[k]; ok {
				src += fmt.Sprintf("    %s = %q\n", k, v)
			}
		}
		src += "    description = \"x\"\n  condition:\n    true\n}\n"
		rules, err := compileSources(map[string]string{"scope.yara": src})
		if err != nil {
			t.Fatalf("compile meta %d: %v", i, err)
		}
		want := newRuleScope(rules.Slice()[0].Metadata())
		got := NewScope(meta)
		for _, tt := range targets {
			var kind *programkind.FileType
			if tt.ext != "" {
				kind = &programkind.FileType{Ext: tt.ext}
			}
			target := NewScopeTarget(kind, tt.path, tt.expath, tt.c)
			wantApplies := want.matches(tt.ext, filepath.ToSlash(trimDisplayPath(tt.path, tt.expath, tt.c)))
			if gotApplies := got.Applies(target); gotApplies != wantApplies {
				t.Errorf("meta %v, target %+v: got = %t, want = %t", meta, tt, gotApplies, wantApplies)
			}
		}
	}
}

func TestGenerateRulesMatchesGenerate(t *testing.T) {
	t.Parallel()
	rules, err := compileSources(map[string]string{
		"exec/shell/a.yara": "rule a_first: medium {\n  meta:\n    description = \"short\"\n  strings:\n    $a = \"curl\"\n  condition:\n    $a\n}\nrule a_second: medium {\n  meta:\n    description = \"a longer description\"\n  strings:\n    $a = \"curl\"\n  condition:\n    $a\n}\n",
		"net/http/b.yara":   "rule b_post: high {\n  strings:\n    $a = \"POST\"\n  condition:\n    $a\n}\n",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	fc := []byte("curl -X POST https://example.com")
	mrs := scanBuf(t, rules, fc)
	c := malcontent.Config{Rules: rules}

	want, err := Generate(t.Context(), "/x/run.sh", mrs, c, "", nil, fc, int64(len(fc)), "sum", nil, 0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	matching := slices.Clone(mrs.MatchingRules())
	rand.New(rand.NewPCG(1, 2)).Shuffle(len(matching), func(i, j int) { matching[i], matching[j] = matching[j], matching[i] })
	got, err := GenerateRules(t.Context(), "/x/run.sh", matching, c, "", nil, fc, int64(len(fc)), "sum", nil, 0)
	if err != nil {
		t.Fatalf("GenerateRules: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GenerateRules:\ngot  = %+v\nwant = %+v", got, want)
	}
	if got, want := HighestMatchRiskRules(matching, nil, "/x/run.sh", "", c), HighestMatchRisk(mrs, nil, "/x/run.sh", "", c); got != want {
		t.Errorf("HighestMatchRiskRules: got = %d, want = %d", got, want)
	}
}

func TestGenerateRulesStopsWhenCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	fr, err := GenerateRules(ctx, "/x/run.sh", nil, malcontent.Config{}, "", nil, nil, 0, "sum", nil, 0)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("GenerateRules error: got = %v, want = %v", err, context.Canceled)
	}
	if fr == nil || !reflect.DeepEqual(*fr, malcontent.FileReport{}) {
		t.Errorf("GenerateRules report: got = %+v, want an empty report", fr)
	}
}

func TestHighestMatchRiskRulesWithoutMatches(t *testing.T) {
	t.Parallel()
	if got := HighestMatchRiskRules(nil, nil, "/x/run.sh", "", malcontent.Config{}); got != 0 {
		t.Errorf("HighestMatchRiskRules(nil): got = %d, want = 0", got)
	}
}

func TestSetRuleOrderOrdersRulesFromOtherSets(t *testing.T) {
	t.Parallel()
	// Two rule sets hold rules of one behavior with equal risk; the rule
	// declared first wins the tie, whichever set it came from.
	tests := []struct {
		name  string
		order map[string]int
		want  string
	}{
		{name: "the universal rule declared first wins", order: map[string]int{"from_universal": 0, "from_scoped": 1}, want: "from_universal"},
		{name: "the scoped rule declared first wins", order: map[string]int{"from_scoped": 0, "from_universal": 1}, want: "from_scoped"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Rule information, order included, is cached per rule set, so
			// each row records its order for rule sets of its own.
			universal, err := compileSources(map[string]string{"exec/shell/a.yara": "rule from_universal: medium {\n  meta:\n    description = \"universal\"\n  strings:\n    $a = \"curl\"\n  condition:\n    $a\n}\n"})
			if err != nil {
				t.Fatalf("compile universal: %v", err)
			}
			scoped, err := compileSources(map[string]string{"exec/shell/a.yara": "rule from_scoped: medium {\n  meta:\n    description = \"scoped\"\n  strings:\n    $a = \"curl\"\n  condition:\n    $a\n}\n"})
			if err != nil {
				t.Fatalf("compile scoped: %v", err)
			}
			fc := []byte("curl")
			matching := append(slices.Clone(scanBuf(t, universal, fc).MatchingRules()), scanBuf(t, scoped, fc).MatchingRules()...)
			SetRuleOrder(universal, func(_, identifier string) (int, bool) {
				i, ok := tt.order[identifier]
				return i, ok
			})
			fr, err := GenerateRules(t.Context(), "/x/run.sh", matching, malcontent.Config{Rules: universal}, "", nil, fc, int64(len(fc)), "sum", nil, 0)
			if err != nil {
				t.Fatalf("GenerateRules: %v", err)
			}
			if len(fr.Behaviors) != 1 || fr.Behaviors[0].RuleName != tt.want {
				t.Errorf("behaviors: got = %+v, want one from %s", fr.Behaviors, tt.want)
			}
		})
	}
}
