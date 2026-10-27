// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"fmt"
	"slices"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// benchBehaviors synthesizes n behaviors with distinct objective/resource/technique segments.
func benchBehaviors(n int) []*malcontent.Behavior {
	objectives := []string{"anti-static", "c2", "persistence", "discovery", "credential"}
	resources := []string{"base64", "http", "launchd", "process", "keychain"}
	techniques := []string{"eval", "exfil", "install", "list", "read"}
	out := make([]*malcontent.Behavior, 0, n)
	for i := range n {
		id := fmt.Sprintf(
			"%s/%s/%s-%d",
			objectives[i%len(objectives)],
			resources[i%len(resources)],
			techniques[i%len(techniques)],
			i,
		)
		out = append(out, &malcontent.Behavior{
			ID:        id,
			RiskScore: 3,
			RiskLevel: "HIGH",
		})
	}
	return out
}

// BenchmarkParseBehaviorID measures the three-segment ID parser.
func BenchmarkParseBehaviorID(b *testing.B) {
	id := "anti-static/base64/eval/inner-technique"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = parseBehaviorID(id)
	}
}

// BenchmarkExtractBehaviors measures the per-FileReport behavior extraction at
// the RESOURCE sensitivity (the default change-detection level).
func BenchmarkExtractBehaviors(b *testing.B) {
	behaviors := benchBehaviors(32)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = extractBehaviors(behaviors, RESOURCE)
	}
}

// BenchmarkBehaviorsChanged compares two FileReports whose behavior sets share
// most entries; this is the typical diff-modified hot path.
func BenchmarkBehaviorsChanged(b *testing.B) {
	src := &malcontent.FileReport{Behaviors: benchBehaviors(32)}
	dest := &malcontent.FileReport{Behaviors: append(benchBehaviors(32), &malcontent.Behavior{
		ID:        "c2/http/new-technique",
		RiskScore: 3,
	})}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = behaviorsChanged(src, dest, RESOURCE)
	}
}

// BenchmarkAlignRoots measures pairing two trees of 100,000 files scanned
// from different roots, the case that pays for choosing the roots.
func BenchmarkAlignRoots(b *testing.B) {
	const n = 100_000
	src, dest := make([]string, 0, n), make([]string, 0, n)
	srcFiles, destFiles := make(map[string]*malcontent.FileReport, n), make(map[string]*malcontent.FileReport, n)
	for i := range n {
		rel := fmt.Sprintf("usr/lib/pkg%03d/mod%06d.so", i%500, i)
		src, dest = append(src, "/build/old/"+rel), append(dest, "/build/new/"+rel)
		srcFiles[src[i]], destFiles[dest[i]] = &malcontent.FileReport{}, &malcontent.FileReport{}
	}
	slices.Sort(src)
	slices.Sort(dest)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = alignRoots(src, dest, srcFiles, destFiles)
	}
}

// BenchmarkFilterDiff exercises the diff-filter predicate at the ALL sensitivity.
func BenchmarkFilterDiff(b *testing.B) {
	ctx := b.Context()
	c := malcontent.Config{Sensitivity: ALL}
	src := &malcontent.FileReport{RiskScore: 2, Behaviors: benchBehaviors(16)}
	dest := &malcontent.FileReport{RiskScore: 3, Behaviors: benchBehaviors(17)}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = filterDiff(ctx, c, src, dest)
	}
}
