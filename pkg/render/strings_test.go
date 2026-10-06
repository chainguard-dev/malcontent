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

func TestBriefRiskColorAbbreviatesLevels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		level string
		want  string
	}{
		{level: report.LevelLOW, want: "LOW"},
		{level: report.LevelMEDIUM, want: "MED"},
		{level: "MED", want: "MED"},
		{level: report.LevelHIGH, want: "HIGH"},
		{level: report.LevelCRITICAL, want: "CRIT"},
		{level: "CRIT", want: "CRIT"},
		{level: report.LevelNONE, want: "NONE"},
		{level: "", want: ""},
	}
	for _, tt := range tests {
		t.Run("level_"+tt.level, func(t *testing.T) {
			t.Parallel()
			if got := renderStripANSI(briefRiskColor(tt.level)); got != tt.want {
				t.Errorf("briefRiskColor(%q): got = %q, want = %q", tt.level, got, tt.want)
			}
		})
	}
}
