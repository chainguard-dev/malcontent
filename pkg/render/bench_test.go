// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
)

// benchFileReport synthesizes a FileReport carrying behaviorCount behaviors.
func benchFileReport(path string, behaviorCount int) *malcontent.FileReport {
	fr := &malcontent.FileReport{
		Path:      path,
		SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Size:      4096,
		RiskScore: 3,
		RiskLevel: "HIGH",
		Behaviors: make([]*malcontent.Behavior, 0, behaviorCount),
	}
	for i := range behaviorCount {
		fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{
			ID:           fmt.Sprintf("anti-static/base64/eval-%d", i),
			Description:  "synthetic behavior description for render bench",
			MatchStrings: []string{"alpha", "beta", "gamma"},
			RiskScore:    3,
			RiskLevel:    "HIGH",
			RuleName:     fmt.Sprintf("rule_%d", i),
		})
	}
	return fr
}

// benchReport builds an in-memory Report with fileCount files, each carrying
// behaviorsPerFile behaviors.
func benchReport(fileCount, behaviorsPerFile int) *malcontent.Report {
	files := xsync.NewMap[string, *malcontent.FileReport]()
	for i := range fileCount {
		path := fmt.Sprintf("/bin/synthetic-%d", i)
		files.Store(path, benchFileReport(path, behaviorsPerFile))
	}
	return &malcontent.Report{Files: files}
}

// BenchmarkTerminal_File renders one FileReport through the Terminal renderer.
func BenchmarkTerminal_File(b *testing.B) {
	ctx := context.Background()
	r := NewTerminal(io.Discard)
	fr := benchFileReport("/bin/synthetic", 8)
	b.ReportAllocs()
	for b.Loop() {
		if err := r.File(ctx, fr); err != nil {
			b.Fatalf("File: %v", err)
		}
	}
}

// BenchmarkBrief_File renders one FileReport through the TerminalBrief renderer.
func BenchmarkBrief_File(b *testing.B) {
	ctx := context.Background()
	r := NewTerminalBrief(io.Discard)
	fr := benchFileReport("/bin/synthetic", 8)
	b.ReportAllocs()
	for b.Loop() {
		if err := r.File(ctx, fr); err != nil {
			b.Fatalf("File: %v", err)
		}
	}
}

// BenchmarkRender_LargeReport drives Terminal.File across a 100-file report.
func BenchmarkRender_LargeReport(b *testing.B) {
	ctx := context.Background()
	r := NewTerminal(io.Discard)
	rep := benchReport(100, 4)
	b.ReportAllocs()
	for b.Loop() {
		rep.Files.Range(func(_ string, fr *malcontent.FileReport) bool {
			if err := r.File(ctx, fr); err != nil {
				b.Fatalf("File: %v", err)
			}
			return true
		})
	}
}

// BenchmarkSanitizeUTF8 exercises the per-string sanitizer fast path.
func BenchmarkSanitizeUTF8(b *testing.B) {
	s := "a regular ASCII description with no special characters at all"
	b.ReportAllocs()
	for b.Loop() {
		_ = sanitizeUTF8(s)
	}
}
