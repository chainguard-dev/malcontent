// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
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

// BenchmarkFilterDiff exercises the diff-filter predicate at the ALL sensitivity.
func BenchmarkFilterDiff(b *testing.B) {
	ctx := context.Background()
	c := malcontent.Config{Sensitivity: ALL}
	src := &malcontent.FileReport{RiskScore: 2, Behaviors: benchBehaviors(16)}
	dest := &malcontent.FileReport{RiskScore: 3, Behaviors: benchBehaviors(17)}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = filterDiff(ctx, c, src, dest)
	}
}
