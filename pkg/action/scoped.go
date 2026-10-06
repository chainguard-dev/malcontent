// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/puzpuzpuz/xsync/v4"

	yarax "github.com/VirusTotal/yara-x/go"
)

// scopedRules serves the scoped rules of a compile.Split. For each file it
// selects the scoped rules that apply, which reports would keep, and scans
// the file with a rule set compiled for just those, so no file is scanned
// with rules meant for other file types.
type scopedRules struct {
	split *compile.Split
	// scopes lists the distinct scopes of the scoped rules, and ruleScope
	// the index in scopes of each scoped rule's scope.
	scopes    []report.Scope
	ruleScope []int
	// sets holds a rule set for each combination of applicable scopes.
	sets *xsync.Map[string, *scopedSet]
}

// scopedSet is a rule set compiled once for one combination of scopes, with
// scanners kept for reuse.
type scopedSet struct {
	once     sync.Once
	rules    *yarax.Rules
	err      error
	scanners sync.Pool
}

var (
	// scopedByUniversal maps a universal rule set to the scoped rules that
	// go with it.
	scopedByUniversal = xsync.NewMap[*yarax.Rules, *scopedRules]()
	// scopedSets maps each compiled scoped rule set to its scanners.
	scopedSets = xsync.NewMap[*yarax.Rules, *scopedSet]()
)

// registerSplit prepares the scoped rules of s for scanning and makes scans
// with s.Universal use them. Reports order the matches of both by the
// declaration order of every rule.
func registerSplit(s *compile.Split) {
	report.SetRuleOrder(s.Universal, func(namespace, identifier string) (int, bool) {
		i, ok := s.Order[compile.RuleKey{Namespace: namespace, Identifier: identifier}]
		return i, ok
	})
	scopedByUniversal.Store(s.Universal, newScopedRules(s))
}

// newScopedRules prepares the scoped rules of s for scanning.
func newScopedRules(s *compile.Split) *scopedRules {
	sr := &scopedRules{split: s, sets: xsync.NewMap[string, *scopedSet]()}
	index := map[string]int{}
	for _, r := range s.Scoped {
		key := scopeKey(r.Meta)
		i, ok := index[key]
		if !ok {
			i = len(sr.scopes)
			index[key] = i
			sr.scopes = append(sr.scopes, report.NewScope(r.Meta))
		}
		sr.ruleScope = append(sr.ruleScope, i)
	}
	return sr
}

// scopeKey renders scoping metadata as a comparable string.
func scopeKey(meta map[string]string) string {
	var key strings.Builder
	for _, k := range []string{"filetypes", "path_include", "path_exclude"} {
		if v, ok := meta[k]; ok {
			key.WriteString(k + "=" + v)
		}
		key.WriteByte(0)
	}
	return key.String()
}

// scopedFor returns the scoped rules that go with the universal rule set
// yrs, or nil when yrs holds every rule.
func scopedFor(yrs *yarax.Rules) *scopedRules {
	sr, _ := scopedByUniversal.Load(yrs)
	return sr
}

// applicable returns the indices of the scoped rules that apply to the file
// at path, of the detected kind, within expath, and a key naming that
// selection.
func (sr *scopedRules) applicable(kind *programkind.FileType, path, expath string, c malcontent.Config) (string, []int) {
	target := report.NewScopeTarget(kind, path, expath, c)
	matched := make([]byte, (len(sr.scopes)+7)/8)
	for i, sc := range sr.scopes {
		if sc.Applies(target) {
			matched[i/8] |= 1 << (i % 8)
		}
	}
	var indices []int
	for i, s := range sr.ruleScope {
		if matched[s/8]&(1<<(s%8)) != 0 {
			indices = append(indices, i)
		}
	}
	return string(matched), indices
}

// set returns the rule set for the scoped rules at indices, compiling it on
// first use.
func (sr *scopedRules) set(ctx context.Context, key string, indices []int) (*yarax.Rules, error) {
	set, _ := sr.sets.LoadOrCompute(key, func() (*scopedSet, bool) { return &scopedSet{}, false })
	set.once.Do(func() {
		set.rules, set.err = sr.split.CompileScoped(ctx, indices)
		if set.err == nil {
			scopedSets.Store(set.rules, set)
		}
	})
	return set.rules, set.err
}

// with runs scan with one of the set's scanners.
func (set *scopedSet) with(scan func(*yarax.Scanner) (*yarax.ScanResults, error)) (*yarax.ScanResults, error) {
	scanner, ok := set.scanners.Get().(*yarax.Scanner)
	if !ok {
		scanner = yarax.NewScanner(set.rules)
	}
	defer set.scanners.Put(scanner)
	return scan(scanner)
}

// forHeader returns the rule sets for the header of fc, the contents of the
// file being scanned, or, when its contents are unknown, every header's.
func (sr *scopedRules) forHeader(fc []byte, known bool) ([]*yarax.Rules, error) {
	if known {
		if len(fc) < 2 {
			return nil, nil
		}
		h, ok := sr.split.ByHeader[[2]byte(fc)]
		if !ok {
			return nil, nil
		}
		rules, err := loadHeader(h)
		if err != nil {
			return nil, err
		}
		return []*yarax.Rules{rules}, nil
	}
	out := make([]*yarax.Rules, 0, len(sr.split.ByHeader))
	for _, h := range sr.split.ByHeader {
		rules, err := loadHeader(h)
		if err != nil {
			return nil, err
		}
		out = append(out, rules)
	}
	return out, nil
}

// loadHeader returns the rule set of h, with scanners kept for reuse.
func loadHeader(h *compile.HeaderRules) (*yarax.Rules, error) {
	rules, err := h.Load()
	if err != nil {
		return nil, err
	}
	scopedSets.LoadOrCompute(rules, func() (*scopedSet, bool) { return &scopedSet{rules: rules}, false })
	return rules, nil
}

// mergeMatches returns the rules that the universal scan results u and the
// scan results of other rule sets matched, each once; reports order them.
func mergeMatches(u *yarax.ScanResults, others ...*yarax.ScanResults) []*yarax.Rule {
	rules := slices.Clone(u.MatchingRules())
	seen := make(map[compile.RuleKey]struct{}, len(rules))
	for _, m := range rules {
		seen[compile.RuleKey{Namespace: m.Namespace(), Identifier: m.Identifier()}] = struct{}{}
	}
	for _, o := range others {
		for _, m := range o.MatchingRules() {
			// A rule set also holds the rules its rules refer to, which other
			// rule sets may hold as well.
			key := compile.RuleKey{Namespace: m.Namespace(), Identifier: m.Identifier()}
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				rules = append(rules, m)
			}
		}
	}
	return rules
}
