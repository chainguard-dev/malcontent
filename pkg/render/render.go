// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

const (
	formatSimple      = "simple"
	formatStrings     = "strings"
	formatInteractive = "interactive"

	// levelCRIT is the abbreviated form of report.LevelCRITICAL used in narrow output.
	levelCRIT = "CRIT"
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
		if isBiDiControl(r) {
			return -1
		}
		return r
	}, s)
	// Replace newlines and carriage returns with spaces to avoid YAML complex key issues
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

// isBiDiControl reports whether r is a BiDi embedding, override, isolate, or
// mark character, which can make displayed text read differently from its bytes.
func isBiDiControl(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	default:
		return r == 0x200E || r == 0x200F // LRM, RLM
	}
}

// sanitizeTerminal makes untrusted text from scanned files safe to print to a
// terminal. Like sanitizeUTF8, it replaces invalid UTF-8 with U+FFFD and drops
// BiDi controls. It also replaces C0 controls (including tab and newline), DEL,
// and C1 controls, which terminals act on by moving the cursor, setting the
// window title, or opening hyperlinks, with the visible escapes strconv.Quote
// uses, such as \x1b, \r, and \u009b. A backslash becomes \\ so an escape
// spelled out in the input reads differently from an escaped control
// character. Other printable text is unchanged.
func sanitizeTerminal(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, string(utf8.RuneError))
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case isBiDiControl(r):
			continue
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
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
	case formatSimple:
		return NewSimple(w), nil
	case formatStrings:
		return NewStringMatches(w), nil
	case formatInteractive:
		t := NewInteractive(w)
		t.Start()
		return t, nil
	default:
		return nil, fmt.Errorf("unknown renderer: %q", kind)
	}
}

// sanitizeFileReport sanitizes a file report entry and stores it in files.
func sanitizeFileReport(path string, r *malcontent.FileReport, files map[string]*malcontent.FileReport) {
	if r == nil || r.Skipped != "" {
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

	pkgStats, _, totalBehaviors := PkgStatistics(c, r.Files)
	riskStats, totalRisks, processedFiles, skippedFiles := RiskStatistics(c, r.Files)

	slices.SortFunc(pkgStats, func(a, b malcontent.StrMetric) int {
		return cmp.Compare(a.Key, b.Key)
	})

	slices.SortFunc(riskStats, func(a, b malcontent.IntMetric) int {
		return cmp.Compare(a.Key, b.Key)
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
