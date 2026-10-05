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

// briefIndent prefixes behavior and wrapped evidence lines in brief output.
var briefIndent = "│" + strings.Repeat(" ", 5)

// briefRender renders fr through the TerminalBrief renderer and returns the visible text.
func briefRender(t *testing.T, fr *malcontent.FileReport) string {
	t.Helper()
	var buf bytes.Buffer
	if err := NewTerminalBrief(&buf).File(t.Context(), fr); err != nil {
		t.Fatalf("File: got err = %v, want = nil", err)
	}
	return renderStripANSI(buf.String())
}

func TestTerminalBriefFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		fr   *malcontent.FileReport
		want string
	}{
		{
			name: "behaviors without evidence each end their own line",
			fr: &malcontent.FileReport{
				Path:      "/bin/tool",
				RiskScore: 2,
				RiskLevel: report.LevelMEDIUM,
				Behaviors: []*malcontent.Behavior{
					{ID: "net/connect", Description: "connects", MatchStrings: []string{"connect"}},
					{ID: "fs/read", Description: "reads files"},
				},
			},
			want: "├─ " + riskEmoji(2) + " /bin/tool\n" +
				briefIndent + "• net/connect — connects\n" +
				briefIndent + "• fs/read — reads files\n",
		},
		{
			name: "short evidence follows the description on the same line",
			fr: &malcontent.FileReport{
				Path:      "/bin/tool",
				RiskScore: 3,
				RiskLevel: report.LevelHIGH,
				Behaviors: []*malcontent.Behavior{
					{ID: "net/connect", Description: "connects", MatchStrings: []string{"AF_INET", "ab", "SOCK_STREAM"}},
					{ID: "fs/read", Description: "reads files"},
				},
			},
			want: "├─ " + riskEmoji(3) + " /bin/tool\n" +
				briefIndent + "• net/connect — connects: AF_INET, SOCK_STREAM\n" +
				briefIndent + "• fs/read — reads files\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := briefRender(t, tt.fr); got != tt.want {
				t.Errorf("File output:\ngot  = %q\nwant = %q", got, tt.want)
			}
		})
	}
}

func TestTerminalBriefFullRejectsDiffs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	rep := &malcontent.Report{Diff: renderDiff(nil, nil, nil)}
	err := NewTerminalBrief(&buf).Full(t.Context(), &malcontent.Config{}, rep)
	if err == nil || !strings.Contains(err.Error(), "diffs are unsupported") {
		t.Errorf("Full error: got = %v, want = diffs are unsupported", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Full output: got = %q, want = empty", buf.String())
	}
}

func TestTerminalBriefEvidenceLayout(t *testing.T) {
	t.Parallel()
	renderRequireNoColor(t)
	width := suggestedWidth()
	render := func(t *testing.T, desc, evidence string) []string {
		t.Helper()
		fr := &malcontent.FileReport{
			Path:      "/bin/x",
			RiskScore: 1,
			RiskLevel: report.LevelLOW,
			Behaviors: []*malcontent.Behavior{
				{ID: "net/connect", Description: desc, MatchStrings: []string{evidence}},
				{ID: "net/listen", Description: "listens"},
			},
		}
		lines := strings.Split(briefRender(t, fr), "\n")
		if len(lines) < 4 {
			t.Fatalf("brief lines: got = %q, want at least 4", lines)
		}
		return lines
	}
	listenLine := briefIndent + "• net/listen — listens"

	const shortDesc = "opens a socket"
	const probe = "qqqqq"
	probeLines := render(t, shortDesc, probe)
	if !strings.HasSuffix(probeLines[1], ": "+probe) {
		t.Fatalf("probe behavior line: got = %q, want suffix %q", probeLines[1], ": "+probe)
	}
	// The width budget covers the behavior line plus evidence, excluding the ": " separator.
	contentLen := len(probeLines[1]) - len(": ") - len(probe)
	longDesc := strings.Repeat("d", width)

	tests := []struct {
		name       string
		desc       string
		evidence   string
		wantSecond string
	}{
		{name: "evidence ending one byte before the width stays inline", desc: shortDesc, evidence: strings.Repeat("q", width-1-contentLen)},
		{name: "evidence reaching the width moves to its own line", desc: shortDesc, evidence: strings.Repeat("q", width-contentLen), wantSecond: briefIndent + strings.Repeat("q", width-contentLen)},
		{name: "evidence longer than the width is truncated with an ellipsis", desc: shortDesc, evidence: strings.Repeat("q", 2*width), wantSecond: briefIndent + strings.Repeat("q", width-1-len(briefIndent)) + "…"},
		{name: "four-byte evidence stays inline past the width", desc: longDesc, evidence: "abcd"},
		{name: "five-byte evidence past the width moves to its own line", desc: longDesc, evidence: "abcde", wantSecond: briefIndent + "abcde"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lines := render(t, tt.desc, tt.evidence)
			next := lines[2]
			if tt.wantSecond == "" {
				if !strings.HasSuffix(lines[1], ": "+tt.evidence) {
					t.Errorf("behavior line: got = %q, want suffix %q", lines[1], ": "+tt.evidence)
				}
			} else {
				if !strings.HasSuffix(lines[1], ":") {
					t.Errorf("behavior line: got = %q, want suffix %q", lines[1], ":")
				}
				if lines[2] != tt.wantSecond {
					t.Errorf("evidence line: got = %q, want = %q", lines[2], tt.wantSecond)
				}
				next = lines[3]
			}
			// The next behavior still renders on its own line after the evidence.
			if next != listenLine {
				t.Errorf("line after evidence: got = %q, want = %q", next, listenLine)
			}
		})
	}
}
