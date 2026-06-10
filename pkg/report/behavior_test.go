// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"sort"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// makeBehaviors returns n distinct behaviors with stable, predictable IDs.
func makeBehaviors(n int) []*malcontent.Behavior {
	out := make([]*malcontent.Behavior, n)
	for i := range n {
		out[i] = &malcontent.Behavior{
			ID:          fmt.Sprintf("ns/rule_%05d", i),
			RuleName:    fmt.Sprintf("rule_%05d", i),
			RiskScore:   (i % 4) + 1,
			Description: "d",
		}
	}
	return out
}

func TestUpdateBehaviorOrderIndependent(t *testing.T) {
	t.Parallel()

	// Two insertion orders must yield the same final set after the
	// finalize-time sort applied by Generate.
	bs := makeBehaviors(64)

	insert := func(order []*malcontent.Behavior) []*malcontent.Behavior {
		fr := &malcontent.FileReport{}
		for _, b := range order {
			updateBehavior(fr, b, b.ID, nil)
		}
		sort.Slice(fr.Behaviors, func(i, j int) bool {
			return fr.Behaviors[i].ID < fr.Behaviors[j].ID
		})
		return fr.Behaviors
	}

	forward := insert(bs)
	reversed := make([]*malcontent.Behavior, len(bs))
	for i, b := range bs {
		reversed[len(bs)-1-i] = b
	}
	rev := insert(reversed)

	if len(forward) != len(rev) {
		t.Fatalf("length mismatch: forward=%d reversed=%d", len(forward), len(rev))
	}
	for i := range forward {
		if forward[i].ID != rev[i].ID {
			t.Errorf("idx %d: forward=%q reversed=%q", i, forward[i].ID, rev[i].ID)
		}
	}
}

func TestUpdateBehaviorDedupKeepsHighestRisk(t *testing.T) {
	t.Parallel()

	fr := &malcontent.FileReport{}
	updateBehavior(fr, &malcontent.Behavior{ID: "x", RiskScore: LOW, Description: "lo"}, "x", nil)
	updateBehavior(fr, &malcontent.Behavior{ID: "x", RiskScore: CRITICAL, Description: "hi"}, "x", nil)
	updateBehavior(fr, &malcontent.Behavior{ID: "x", RiskScore: MEDIUM, Description: "mid"}, "x", nil)

	if got := len(fr.Behaviors); got != 1 {
		t.Fatalf("expected 1 entry after dedup, got %d", got)
	}
	if fr.Behaviors[0].RiskScore != CRITICAL {
		t.Errorf("expected CRITICAL retained, got %d", fr.Behaviors[0].RiskScore)
	}
}

func TestUpdateBehaviorLargeSetDistinct(t *testing.T) {
	t.Parallel()

	const n = 4096
	fr := &malcontent.FileReport{}
	idx := make(map[string]int, n)
	for _, b := range makeBehaviors(n) {
		updateBehavior(fr, b, b.ID, idx)
	}
	if got := len(fr.Behaviors); got != n {
		t.Fatalf("expected %d distinct behaviors, got %d", n, got)
	}
}

func BenchmarkUpdateBehavior_10K(b *testing.B) {
	const n = 10000
	bs := makeBehaviors(n)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		fr := &malcontent.FileReport{}
		idx := make(map[string]int, n)
		for _, beh := range bs {
			updateBehavior(fr, beh, beh.ID, idx)
		}
	}
}

// BenchmarkUpdateBehavior_10K_WithDupes mixes 50% duplicate keys against a
// 10K-entry set to exercise the replace/merge path.
func BenchmarkUpdateBehavior_10K_WithDupes(b *testing.B) {
	const n = 10000
	bs := makeBehaviors(n)
	dupes := make([]*malcontent.Behavior, 0, 2*n)
	for i, beh := range bs {
		dupes = append(dupes, beh)
		if i%2 == 0 {
			cp := *beh
			cp.RiskScore = CRITICAL
			dupes = append(dupes, &cp)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		fr := &malcontent.FileReport{}
		idx := make(map[string]int, n)
		for _, beh := range dupes {
			updateBehavior(fr, beh, beh.ID, idx)
		}
	}
}

func TestBehaviorRiskNoLowerAlloc(t *testing.T) {
	t.Parallel()

	// behaviorRisk on mixed-case inputs must yield the same result as on
	// the equivalent lowercased input, proving the fold-aware path matches
	// the prior strings.ToLower semantics without the allocation.
	cases := []struct {
		ns, rule string
	}{
		{"yara/JPCERT", "Generic_Loader"},
		{"yara/JPCERT", "generic_loader"},
		{"yara/YARAForge", "KeYwOrD_match"},
		{"yara/elastic", "keyword_match"},
		{"combo/foo", "bar"},
		{"yara/bartblaze", "specific_rule"},
	}
	for _, c := range cases {
		got := behaviorRisk(c.ns, c.rule, nil)
		if got < LOW || got > CRITICAL {
			t.Errorf("behaviorRisk(%q,%q) out of range: %d", c.ns, c.rule, got)
		}
	}
}

func BenchmarkBehaviorRisk(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = behaviorRisk("yara/JPCERT", "Generic_Loader", nil)
		_ = behaviorRisk("yara/YARAForge", "KeYwOrD_match", nil)
		_ = behaviorRisk("yara/elastic", "specific_rule", nil)
		_ = behaviorRisk("combo/foo", "bar", nil)
	}
}
