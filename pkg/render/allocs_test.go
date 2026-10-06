// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"io"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

// testing.AllocsPerRun counts allocations process-wide, so this test does not
// run in parallel.
func TestTextHelperAllocations(t *testing.T) {
	// plain needs no escaping in any format and is longer than the 8 bytes a
	// builder starts with, so growing it byte by byte would allocate repeatedly.
	const plain = "abcdefghijklmnopqrstuvwxyz0123456789abcd"
	ctx := t.Context()
	md := NewMarkdown(io.Discard)
	skipped := &malcontent.FileReport{
		Path:      "/bin/skipped",
		Skipped:   "data file",
		Behaviors: []*malcontent.Behavior{{ID: "net/connect", RiskScore: 3, RiskLevel: report.LevelHIGH}},
	}
	tests := []struct {
		name string
		run  func()
		want float64
	}{
		{name: "terminal text that needs no escaping is returned as is", run: func() { _ = sanitizeTerminal("plain text ~ with spaces") }, want: 0},
		{name: "terminal text that drops a BiDi control is built in one allocation", run: func() { _ = sanitizeTerminal("\u202e" + plain) }, want: 1},
		{name: "Markdown text is built in one allocation", run: func() { _ = sanitizeMarkdown(plain) }, want: 1},
		{name: "Markdown URL link allocates its text, its destination, and the link", run: func() { _ = markdownURLLink(plain) }, want: 3},
		{name: "single Markdown evidence link is not copied", run: func() { _ = markdownEvidence([]string{"abc"}) }, want: 2},
		{name: "evidence line that fits is returned as is", run: func() { _ = wrapLine("abcd", 4) }, want: 0},
		{name: "Markdown file returns at once for a skipped report", run: func() { _ = md.File(ctx, skipped) }, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(100, tt.run); got != tt.want {
				t.Errorf("allocations: got = %v, want = %v", got, tt.want)
			}
		})
	}
}
