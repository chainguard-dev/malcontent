// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"sort"

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
