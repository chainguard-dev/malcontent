// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

func TestStringMatchesFileListsRulesWithStrings(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{
		Path:      "/sbin/ping",
		RiskScore: 4,
		RiskLevel: report.LevelCRITICAL,
		Behaviors: []*malcontent.Behavior{
			{RuleName: "zz_scan_tool", RiskScore: 2, MatchStrings: []string{"connect", "socket"}},
			{RuleName: "mm_no_strings", RiskScore: 3},
			{RuleName: "aa_ifaddrs", RiskScore: 1, MatchStrings: []string{"getifaddrs"}},
		},
	}
	// Rules print in name order, and rules without matched strings are omitted.
	want := "Matches for /sbin/ping [CRIT] (2 rules):\n" +
		"aa_ifaddrs [LOW] (1 string): \n- getifaddrs\n" +
		"zz_scan_tool [MED] (2 strings): \n- connect\n- socket\n"

	var buf bytes.Buffer
	if err := NewStringMatches(&buf).File(t.Context(), fr); err != nil {
		t.Fatalf("File: got err = %v, want = nil", err)
	}
	if got := renderStripANSI(buf.String()); got != want {
		t.Errorf("File output:\ngot  = %q\nwant = %q", got, want)
	}
}

func TestStringMatchesFullRejectsDiffs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	rep := &malcontent.Report{Diff: renderDiff(nil, nil, nil)}
	err := NewStringMatches(&buf).Full(t.Context(), &malcontent.Config{}, rep)
	if err == nil || !strings.Contains(err.Error(), "diffs are unsupported") {
		t.Errorf("Full error: got = %v, want = diffs are unsupported", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Full output: got = %q, want = empty", buf.String())
	}
}

func TestBriefRiskAbbreviatesLevels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		level     string
		want      string
		wantColor sgr
	}{
		{level: report.LevelLOW, want: "LOW", wantColor: colorPalette.hiGreen},
		{level: report.LevelMEDIUM, want: "MED", wantColor: colorPalette.hiYellow},
		{level: "MED", want: "MED", wantColor: colorPalette.hiYellow},
		{level: report.LevelHIGH, want: "HIGH", wantColor: colorPalette.hiRed},
		{level: report.LevelCRITICAL, want: "CRIT", wantColor: colorPalette.hiMagenta},
		{level: "CRIT", want: "CRIT", wantColor: colorPalette.hiMagenta},
		{level: report.LevelNONE, want: "NONE", wantColor: colorPalette.white},
		{level: "", want: "", wantColor: colorPalette.white},
	}
	for _, tt := range tests {
		t.Run("level_"+tt.level, func(t *testing.T) {
			t.Parallel()
			gotColor, got := colorPalette.briefRisk(tt.level)
			if got != tt.want {
				t.Errorf("briefRisk(%q) label: got = %q, want = %q", tt.level, got, tt.want)
			}
			if gotColor != tt.wantColor {
				t.Errorf("briefRisk(%q) color: got = %q, want = %q", tt.level, gotColor.on, tt.wantColor.on)
			}
			if _, plain := plainPalette.briefRisk(tt.level); plain != tt.want {
				t.Errorf("plain briefRisk(%q) label: got = %q, want = %q", tt.level, plain, tt.want)
			}
		})
	}
}
