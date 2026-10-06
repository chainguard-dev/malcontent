// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

// concurrencyReport returns a fresh report for file i whose output spans many
// lines, including evidence long enough to move to a line of its own.
func concurrencyReport(i int) *malcontent.FileReport {
	return &malcontent.FileReport{
		Path:      fmt.Sprintf("/bin/file-%03d", i),
		RiskScore: 3,
		RiskLevel: report.LevelHIGH,
		Behaviors: []*malcontent.Behavior{
			{ID: "net/connect", Description: "connects", MatchStrings: []string{"AF_INET", strings.Repeat("x", 200)}, RiskScore: 3, RiskLevel: report.LevelHIGH, RuleName: "connect", RuleURL: "https://r/connect"},
			{ID: "fs/read", Description: "reads files", MatchStrings: []string{"fopen"}, RiskScore: 1, RiskLevel: report.LevelLOW, RuleName: "read", RuleURL: "https://r/read"},
			{ID: "exec/shell", Description: "runs a shell", RiskScore: 2, RiskLevel: report.LevelMEDIUM, RuleName: "shell", RuleURL: "https://r/shell"},
		},
	}
}

// concurrencyRequireBlocks fails unless out is every block in blocks, each
// exactly once and whole, in any order. No block may start another.
func concurrencyRequireBlocks(t *testing.T, out string, blocks []string) {
	t.Helper()
	remaining := make(map[int]struct{}, len(blocks))
	for i := range blocks {
		remaining[i] = struct{}{}
	}
	for pos := 0; pos < len(out); {
		found := -1
		for i := range remaining {
			if strings.HasPrefix(out[pos:], blocks[i]) {
				found = i
				break
			}
		}
		if found < 0 {
			t.Fatalf("output at byte %d: got = %q, want the start of a whole block", pos, out[pos:min(len(out), pos+160)])
		}
		delete(remaining, found)
		pos += len(blocks[found])
	}
	if len(remaining) > 0 {
		t.Errorf("blocks in output: got = %d, want = %d", len(blocks)-len(remaining), len(blocks))
	}
}

func TestTextRenderersKeepEachFileContiguous(t *testing.T) {
	t.Parallel()
	const files = 64
	scanPath := func(i int) string { return fmt.Sprintf("/scan/path-%03d", i) }

	for _, r := range renderTextRenderers() {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			// Render each scanning line and each file alone to learn its block.
			blocks := make([]string, 0, 2*files)
			for i := range files {
				var line, file bytes.Buffer
				r.newRenderer(&line).Scanning(t.Context(), scanPath(i))
				if line.Len() > 0 {
					blocks = append(blocks, line.String())
				}
				if err := r.newRenderer(&file).File(t.Context(), concurrencyReport(i)); err != nil {
					t.Fatalf("File: got err = %v, want = nil", err)
				}
				blocks = append(blocks, file.String())
			}

			// A bytes.Buffer is not safe for concurrent writes, so the race
			// detector also reports any write the renderer fails to serialize.
			var out bytes.Buffer
			shared := r.newRenderer(&out)
			errs := make([]error, files)
			var wg sync.WaitGroup
			for i := range files {
				wg.Go(func() {
					shared.Scanning(t.Context(), scanPath(i))
					errs[i] = shared.File(t.Context(), concurrencyReport(i))
				})
			}
			wg.Wait()

			for i, err := range errs {
				if err != nil {
					t.Fatalf("File %d: got err = %v, want = nil", i, err)
				}
			}
			concurrencyRequireBlocks(t, out.String(), blocks)
		})
	}
}
