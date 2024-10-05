// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// String matches renderer
//
// Example:
//
// Displaying matches for /sbin/ping [MED]
// ---------------------------------------
// _connect [MED]:
// - _connect
// bsd_if [LOW]:
// - if_nametoindex
// bsd_ifaddrs [MED]:
// - freeifaddrs
// - getifaddrs
// generic_scan_tool [MED]:
// - connect
// - gethostbyname
// - port
// - scan
// - socket
// gethostbyaddr [LOW]:
// - gethostbyaddr
// ...

package render

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/fatih/color"
)

// Map to handle RiskScore -> RiskLevel conversions.
var riskLevels = map[int]string{
	0: "NONE",     // harmless: common to all executables, no system impact
	1: "LOW",      // undefined: low impact, common to good and bad executables
	2: "MEDIUM",   // notable: may have impact, but common
	3: "HIGH",     // suspicious: uncommon, but could be legit
	4: "CRITICAL", // critical: certainly malware
}

type StringMatches struct {
	w io.Writer
}

func NewStringMatches(w io.Writer) StringMatches {
	return StringMatches{w: w}
}

type Match struct {
	Description string
	Risk        int
	Rule        string
	Strings     []string
}

func (r StringMatches) File(_ context.Context, fr *malcontent.FileReport) error {
	if len(fr.Behaviors) == 0 {
		return nil
	}

	matches := []Match{}
	sort.Slice(fr.Behaviors, func(i, j int) bool {
		return fr.Behaviors[i].RuleName < fr.Behaviors[j].RuleName
	})
	for _, b := range fr.Behaviors {
		if len(b.MatchStrings) > 0 {
			matches = append(matches, Match{
				Risk:    b.RiskScore,
				Rule:    b.RuleName,
				Strings: b.MatchStrings,
			})
		}
	}

	prefix := "Matches for"
	rUnit := plural("rule", len(matches))
	fmt.Fprintf(r.w, "%s %s %s%s%s %s%s %s%s:\n", prefix, color.HiGreenString(fr.Path), color.HiBlackString("["), briefRiskColor(fr.RiskLevel), color.HiBlackString("]"), color.HiBlackString("("), color.HiGreenString(fmt.Sprintf("%d", len(matches))), color.HiGreenString(rUnit), color.HiBlackString(")"))
	for _, m := range matches {
		sUnit := plural("string", len(m.Strings))
		fmt.Fprintf(r.w, "%s %s%s%s %s%s %s%s: \n%s%s\n", color.HiCyanString(m.Rule), color.HiBlackString("["), briefRiskColor(riskLevels[m.Risk]), color.HiBlackString("]"), color.HiBlackString("("), color.HiGreenString(fmt.Sprintf("%d", len(m.Strings))), color.HiGreenString(sUnit), color.HiBlackString(")"), color.HiBlackString("- "), strings.Join(m.Strings, color.HiBlackString("\n- ")))
	}

	return nil
}

func (r StringMatches) Full(_ context.Context, rep *malcontent.Report) error {
	// Non-diff files are handled on the fly by File()
	if rep.Diff == nil {
		return nil
	}

	return fmt.Errorf("diffs are unsupported by the StringMatches renderer")
}

// plural returns a pluralized string if the length of l is greater than 1.
func plural(s string, l int) string {
	if l > 1 {
		return fmt.Sprintf("%ss", s)
	}
	return s
}
