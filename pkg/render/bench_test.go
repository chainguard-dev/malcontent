// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/fatih/color"
	"github.com/puzpuzpuz/xsync/v4"
)

// benchFileReport synthesizes a FileReport carrying behaviorCount behaviors.
func benchFileReport(path string, behaviorCount int) *malcontent.FileReport {
	fr := &malcontent.FileReport{
		Path:      path,
		SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Size:      4096,
		RiskScore: 3,
		RiskLevel: report.LevelHIGH,
		Behaviors: make([]*malcontent.Behavior, 0, behaviorCount),
	}
	for i := range behaviorCount {
		fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{
			ID:           fmt.Sprintf("anti-static/base64/eval-%d", i),
			Description:  "synthetic behavior description for render bench",
			MatchStrings: []string{"alpha", "beta", "gamma"},
			RiskScore:    3,
			RiskLevel:    report.LevelHIGH,
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
	ctx := b.Context()
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
	ctx := b.Context()
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
	ctx := b.Context()
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

// benchNamespaces spreads synthetic behaviors across namespaces whose long
// names have several lengths.
var benchNamespaces = []string{"net", "fs", "exec", "c2", "crypto", "anti-static", "sus", "persist"}

// benchRichFileReport synthesizes a FileReport whose behaviors span several
// namespaces and risk levels, often name an author, and carry evidence that is
// sometimes long enough to move to a line of its own.
func benchRichFileReport(path string, behaviorCount int) *malcontent.FileReport {
	fr := &malcontent.FileReport{
		Path:      path,
		SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Size:      8192,
		RiskScore: 3,
		RiskLevel: report.LevelHIGH,
		Behaviors: make([]*malcontent.Behavior, 0, behaviorCount),
	}
	for i := range behaviorCount {
		score := i%4 + 1
		evidence := []string{"alpha", fmt.Sprintf("symbol_%d", i), "ab"}
		if i%5 == 0 {
			evidence = append(evidence, strings.Repeat("long-evidence-", 12))
		}
		author := ""
		if i%3 == 0 {
			author = "Synthetic Author"
		}
		fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{
			ID:           fmt.Sprintf("%s/technique/variant-%d", benchNamespaces[i%len(benchNamespaces)], i),
			Description:  "synthetic behavior description - with more detail",
			MatchStrings: evidence,
			RiskScore:    score,
			RiskLevel:    riskLevels[score],
			RuleName:     fmt.Sprintf("rule_%d", i),
			RuleAuthor:   author,
			RuleURL:      "https://github.com/chainguard-dev/malcontent/blob/main/rules/synthetic.yara#L1",
		})
	}
	return fr
}

// benchRichReports returns fileCount rich file reports.
func benchRichReports(fileCount, behaviorsPerFile int) []*malcontent.FileReport {
	frs := make([]*malcontent.FileReport, 0, fileCount)
	for i := range fileCount {
		frs = append(frs, benchRichFileReport(fmt.Sprintf("/usr/lib/synthetic/file-%05d.so", i), behaviorsPerFile))
	}
	return frs
}

// benchRichReport returns a Report holding fileCount rich file reports.
func benchRichReport(fileCount, behaviorsPerFile int) *malcontent.Report {
	files := xsync.NewMap[string, *malcontent.FileReport]()
	for _, fr := range benchRichReports(fileCount, behaviorsPerFile) {
		files.Store(fr.Path, fr)
	}
	return &malcontent.Report{Files: files}
}

// benchColorModes are the fatih/color settings the text renderer benchmarks run under.
var benchColorModes = []struct {
	name    string
	noColor bool
}{
	{name: "plain", noColor: true},
	{name: "color", noColor: false},
}

// benchSetColor sets color.NoColor for one benchmark and restores it afterward.
func benchSetColor(b *testing.B, noColor bool) {
	b.Helper()
	saved := color.NoColor
	color.NoColor = noColor
	b.Cleanup(func() { color.NoColor = saved })
}

// benchFiles renders every report through newRenderer's File method in each loop.
func benchFiles(b *testing.B, newRenderer func(io.Writer) malcontent.Renderer, frs []*malcontent.FileReport) {
	b.Helper()
	for _, mode := range benchColorModes {
		b.Run(mode.name, func(b *testing.B) {
			benchSetColor(b, mode.noColor)
			ctx := b.Context()
			r := newRenderer(io.Discard)
			b.ReportAllocs()
			for b.Loop() {
				for _, fr := range frs {
					if err := r.File(ctx, fr); err != nil {
						b.Fatalf("File: %v", err)
					}
				}
			}
		})
	}
}

// BenchmarkTerminalFile renders 200 files of 24 behaviors each through the Terminal renderer.
func BenchmarkTerminalFile(b *testing.B) {
	benchFiles(b, func(w io.Writer) malcontent.Renderer { return NewTerminal(w) }, benchRichReports(200, 24))
}

// BenchmarkTerminalBriefFile renders 200 files of 24 behaviors each through the TerminalBrief renderer.
func BenchmarkTerminalBriefFile(b *testing.B) {
	benchFiles(b, func(w io.Writer) malcontent.Renderer { return NewTerminalBrief(w) }, benchRichReports(200, 24))
}

// BenchmarkSimpleFile renders 200 files of 24 behaviors each through the Simple renderer.
func BenchmarkSimpleFile(b *testing.B) {
	benchFiles(b, func(w io.Writer) malcontent.Renderer { return NewSimple(w) }, benchRichReports(200, 24))
}

// BenchmarkMarkdownFile renders 200 files of 24 behaviors each through the Markdown renderer.
func BenchmarkMarkdownFile(b *testing.B) {
	benchFiles(b, func(w io.Writer) malcontent.Renderer { return NewMarkdown(w) }, benchRichReports(200, 24))
}

// BenchmarkTerminalFileParallel renders files from every CPU at once, as scan
// workers do, through one Terminal renderer.
func BenchmarkTerminalFileParallel(b *testing.B) {
	frs := benchRichReports(64, 24)
	r := NewTerminal(io.Discard)
	ctx := b.Context()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if err := r.File(ctx, frs[i%len(frs)]); err != nil {
				b.Errorf("File: %v", err)
				return
			}
			i++
		}
	})
}

// BenchmarkJSONFull serializes a 2,000-file report through the JSON renderer.
func BenchmarkJSONFull(b *testing.B) {
	ctx := b.Context()
	rep := benchRichReport(2000, 16)
	r := NewJSON(io.Discard)
	b.ReportAllocs()
	for b.Loop() {
		if err := r.Full(ctx, &malcontent.Config{}, rep); err != nil {
			b.Fatalf("Full: %v", err)
		}
	}
}

// BenchmarkYAMLFull serializes a 500-file report through the YAML renderer.
func BenchmarkYAMLFull(b *testing.B) {
	ctx := b.Context()
	rep := benchRichReport(500, 16)
	r := NewYAML(io.Discard)
	b.ReportAllocs()
	for b.Loop() {
		if err := r.Full(ctx, &malcontent.Config{}, rep); err != nil {
			b.Fatalf("Full: %v", err)
		}
	}
}
