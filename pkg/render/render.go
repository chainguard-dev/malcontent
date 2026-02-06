// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// Report stores a JSON- or YAML-friendly representation of File Reports.
type Report struct {
	Diff   *malcontent.DiffReport            `json:",omitempty" yaml:",omitempty"`
	Files  map[string]*malcontent.FileReport `json:",omitempty" yaml:",omitempty"`
	Filter string                            `json:",omitempty" yaml:",omitempty"`
	Stats  *Stats                            `json:",omitempty" yaml:",omitempty"`
}

// Stats stores a JSON- or YAML-friendly Statistics report.
type Stats struct {
	PkgStats       []malcontent.StrMetric `json:",omitempty" yaml:",omitempty"`
	ProcessedFiles int                    `json:",omitempty" yaml:",omitempty"`
	RiskStats      []malcontent.IntMetric `json:",omitempty" yaml:",omitempty"`
	SkippedFiles   int                    `json:",omitempty" yaml:",omitempty"`
	TotalBehaviors int                    `json:",omitempty" yaml:",omitempty"`
	TotalRisks     int                    `json:",omitempty" yaml:",omitempty"`
}

// sanitizeUTF8 replaces invalid UTF-8 sequences with the Unicode replacement character
// and replaces newlines/carriage returns with spaces to prevent YAML serialization issues.
// This ensures consistent handling across JSON and YAML serialization.
func sanitizeUTF8(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, string(utf8.RuneError))
	}
	// Strip BiDi override characters that can confuse visual display
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 0x202A && r <= 0x202E: // LRE, RLE, PDF, LRO, RLO
			return -1
		case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
			return -1
		case r == 0x200E || r == 0x200F: // LRM, RLM
			return -1
		default:
			return r
		}
	}, s)
	// Replace newlines and carriage returns with spaces to avoid YAML complex key issues
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

// New returns a new Renderer.
func New(kind string, w io.Writer) (malcontent.Renderer, error) {
	switch kind {
	case "", "auto", "terminal":
		return NewTerminal(w), nil
	case "terminal_brief":
		return NewTerminalBrief(w), nil
	case "markdown":
		return NewMarkdown(w), nil
	case "yaml":
		return NewYAML(w), nil
	case "json":
		return NewJSON(w), nil
	case "simple":
		return NewSimple(w), nil
	case "strings":
		return NewStringMatches(w), nil
	case "interactive":
		t := NewInteractive(w)
		t.Start()
		return t, nil
	default:
		return nil, fmt.Errorf("unknown renderer: %q", kind)
	}
}

// sanitizeFileReport sanitizes a sync.Map entry and stores it in files.
// Returns false only if iteration should stop (never in this implementation).
func sanitizeFileReport(key, value any, files map[string]*malcontent.FileReport) {
	path, ok := key.(string)
	if !ok {
		return
	}

	r, ok := value.(*malcontent.FileReport)
	if !ok || r.Skipped != "" {
		return
	}

	r.ArchiveRoot = ""
	r.FullPath = ""
	r.Path = sanitizeUTF8(r.Path)

	for _, b := range r.Behaviors {
		if b != nil {
			b.ID = sanitizeUTF8(b.ID)
			b.Description = sanitizeUTF8(b.Description)
		}
	}

	files[sanitizeUTF8(path)] = r
}

func riskEmoji(score int) string {
	symbol := "🔵"
	switch score {
	case 2:
		symbol = "🟡"
	case 3:
		symbol = "🛑"
	case 4:
		symbol = "😈"
	}

	return symbol
}

func serializedStats(c *malcontent.Config, r *malcontent.Report) *Stats {
	// guard against nil reports
	if r == nil {
		return nil
	}

	pkgStats, _, totalBehaviors := PkgStatistics(c, &r.Files)
	riskStats, totalRisks, processedFiles, skippedFiles := RiskStatistics(c, &r.Files)

	sort.Slice(pkgStats, func(i, j int) bool {
		return pkgStats[i].Key < pkgStats[j].Key
	})

	sort.Slice(riskStats, func(i, j int) bool {
		return riskStats[i].Key < riskStats[j].Key
	})

	return &Stats{
		PkgStats:       pkgStats,
		ProcessedFiles: processedFiles,
		RiskStats:      riskStats,
		SkippedFiles:   skippedFiles,
		TotalBehaviors: totalBehaviors,
		TotalRisks:     totalRisks,
	}
}
