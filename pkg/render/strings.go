// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// String matches renderer
//
// Example:
//
// Matches for /sbin/ping [MED] (15 rules):
// _connect [MED] (1 string):
// - _connect
// bsd_if [LOW] (1 string):
// - if_nametoindex
// bsd_ifaddrs [MED] (2 strings):
// - freeifaddrs
// - getifaddrs
// generic_scan_tool [MED] (5 strings):
// - connect
// - gethostbyname
// - port
// - scan
// - socket
// ...

package render

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

// Map to handle RiskScore -> RiskLevel conversions.
var riskLevels = map[int]string{
	0: report.LevelNONE,     // harmless: common to all executables, no system impact
	1: report.LevelLOW,      // undefined: low impact, common to good and bad executables
	2: report.LevelMEDIUM,   // notable: may have impact, but common
	3: report.LevelHIGH,     // suspicious: uncommon, but could be legit
	4: report.LevelCRITICAL, // critical: certainly malware
}

// StringMatches lists the strings each rule matched as the scan reports each
// file. It is safe for concurrent use: each File call writes its output with
// a single Write.
type StringMatches struct {
	out blockWriter
}

func NewStringMatches(w io.Writer) *StringMatches {
	return &StringMatches{out: blockWriter{w: w}}
}

type Match struct {
	Description string
	Risk        int
	Rule        string
	Strings     []string
}

func (r *StringMatches) Name() string { return "TerminalStrings" }

func (r *StringMatches) Scanning(_ context.Context, path string) {
	r.out.scanning(path)
}

func (r *StringMatches) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr.Skipped != "" || len(fr.Behaviors) == 0 {
		return nil
	}

	matches := make([]Match, 0, len(fr.Behaviors))
	slices.SortFunc(fr.Behaviors, func(a, b *malcontent.Behavior) int {
		return cmp.Compare(a.RuleName, b.RuleName)
	})
	for _, bh := range fr.Behaviors {
		if len(bh.MatchStrings) > 0 {
			matched := make([]string, 0, len(bh.MatchStrings))
			for _, ms := range bh.MatchStrings {
				matched = append(matched, sanitizeTerminal(ms))
			}
			matches = append(matches, Match{
				Risk:    bh.RiskScore,
				Rule:    bh.RuleName,
				Strings: matched,
			})
		}
	}

	p := currentPalette()
	b := getBuffer()
	defer putBuffer(b)

	b.WriteString("Matches for ")
	p.hiGreen.wrap(b, sanitizeTerminal(fr.Path))
	b.WriteByte(' ')
	writeMatchCounts(b, p, fr.RiskLevel, len(matches), "rule")
	b.WriteString(":\n")
	for _, m := range matches {
		p.hiCyan.wrap(b, m.Rule)
		b.WriteByte(' ')
		writeMatchCounts(b, p, riskLevels[m.Risk], len(m.Strings), "string")
		b.WriteString(": \n")
		p.hiBlack.wrap(b, "- ")
		for i, s := range m.Strings {
			if i > 0 {
				p.hiBlack.wrap(b, "\n- ")
			}
			b.WriteString(s)
		}
		b.WriteByte('\n')
	}

	return r.out.write(b.Bytes())
}

// writeMatchCounts writes a bracketed risk level followed by a count of noun
// in parentheses, such as "[HIGH] (2 rules)".
func writeMatchCounts(b *bytes.Buffer, p *palette, level string, n int, noun string) {
	s, label := p.briefRisk(level)
	p.hiBlack.wrap(b, "[")
	s.wrap(b, label)
	p.hiBlack.wrap(b, "]")
	b.WriteByte(' ')
	p.hiBlack.wrap(b, "(")
	p.hiGreen.wrap(b, strconv.Itoa(n))
	b.WriteByte(' ')
	p.hiGreen.wrap(b, plural(noun, n))
	p.hiBlack.wrap(b, ")")
}

func (r *StringMatches) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// guard against nil reports
	// Non-diff files are handled on the fly by File()
	if rep == nil || rep.Diff == nil {
		return nil
	}

	return fmt.Errorf("diffs are unsupported by the StringMatches renderer")
}

// plural returns a pluralized string if the length of l is greater than 1.
func plural(s string, l int) string {
	if l > 1 {
		return s + "s"
	}
	return s
}
