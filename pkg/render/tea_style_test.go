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

// teaSummary renders fr through renderFileSummaryTea and returns the visible text with whitespace collapsed.
func teaSummary(t *testing.T, fr *malcontent.FileReport) string {
	t.Helper()
	var buf bytes.Buffer
	renderFileSummaryTea(t.Context(), fr, &buf, tableConfig{Title: fr.Path})
	return renderSquash(buf.String())
}

func TestWrapLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		text  string
		width int
		want  string
	}{
		{name: "shorter than width is unchanged", text: "abc", width: 4, want: "abc"},
		{name: "exactly width is unchanged", text: "abcd", width: 4, want: "abcd"},
		{name: "two full chunks", text: "abcdefgh", width: 4, want: "abcd\n      efgh"},
		{name: "remainder on a final indented line", text: "abcdefghij", width: 4, want: "abcd\n      efgh\n      ij"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := wrapLine(tt.text, tt.width); got != tt.want {
				t.Errorf("wrapLine(%q, %d): got = %q, want = %q", tt.text, tt.width, got, tt.want)
			}
		})
	}
}

func TestCleanAndWrapEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		evidence string
		width    int
		want     string
	}{
		{name: "each comma-separated match gets its own indented line", evidence: "alpha, beta", width: 70, want: "      alpha\n      beta"},
		{name: "escape sequences are decoded", evidence: `\x41\x42`, width: 70, want: "      AB"},
		{name: "invalid escape sequences keep a visible backslash", evidence: `bad\q`, width: 70, want: `      bad\\q`},
		{name: "decoded control characters are shown escaped", evidence: `a\x1b[2Jb`, width: 70, want: `      a\x1b[2Jb`},
		{name: "embedded quotes are kept verbatim", evidence: `say "hi"`, width: 70, want: `      say "hi"`},
		{name: "match longer than width wraps", evidence: "abcdefghij", width: 4, want: "      abcd\n      efgh\n      ij"},
		{name: "match exactly width does not wrap", evidence: "abcd", width: 4, want: "      abcd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := cleanAndWrapEvidence(tt.evidence, tt.width); got != tt.want {
				t.Errorf("cleanAndWrapEvidence(%q, %d): got = %q, want = %q", tt.evidence, tt.width, got, tt.want)
			}
		})
	}
}

func TestRenderFileSummaryTeaScanMode(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{
		Path:      "/bin/evil",
		RiskScore: 3,
		RiskLevel: report.LevelHIGH,
		Behaviors: []*malcontent.Behavior{
			{ID: "net/connect", Description: "connects to hosts - over TCP", MatchStrings: []string{"AF_INET"}, RiskScore: 3, RiskLevel: report.LevelHIGH, RuleAuthor: "Alice"},
			{ID: "crypto/aes", RiskScore: 2, RiskLevel: report.LevelMEDIUM, RuleAuthor: "Bob"},
			{ID: "c2/beacon", Description: "beacons home", MatchStrings: []string{`\x41\x42C`}, RiskScore: 4, RiskLevel: report.LevelCRITICAL},
		},
	}
	got := teaSummary(t, fr)
	// Namespaces sort alphabetically by long name; evidence escapes are decoded.
	want := []string{
		"/bin/evil HIGH",
		"command & control CRITICAL",
		"• CRIT beacon beacons home",
		"ABC",
		"cryptography MEDIUM",
		"• MED aes by Bob",
		"networking HIGH",
		"• HIGH connect connects to hosts, by Alice",
		"AF_INET",
	}
	if !renderIndexOrder(got, want...) {
		t.Errorf("renderFileSummaryTea output: got = %q, want in order %q", got, want)
	}
	if strings.Contains(got, "→") {
		t.Errorf("renderFileSummaryTea output: got = %q, want no risk transitions", got)
	}
}

func TestRenderFileSummaryTeaDiffMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		fr     *malcontent.FileReport
		want   []string
		absent []string
	}{
		{
			name: "changed behaviors show transitions and hide unchanged ones",
			fr: &malcontent.FileReport{
				Path:      "/bin/mod",
				RiskScore: 3,
				RiskLevel: report.LevelHIGH,
				Behaviors: []*malcontent.Behavior{
					{ID: "net/bind", Description: "binds a port", RiskScore: 1, RiskLevel: report.LevelLOW},
					{ID: "net/connect", Description: "connects", MatchStrings: []string{"AF_INET"}, RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
					{ID: "exec/system", Description: "calls system", RiskScore: 1, RiskLevel: report.LevelLOW},
					{ID: "exec/shell", Description: "runs a shell", MatchStrings: []string{"/bin/sh"}, RiskScore: 3, RiskLevel: report.LevelHIGH, DiffRemoved: true},
				},
			},
			want: []string{
				"Changed (1 added, 1 removed): /bin/mod HIGH",
				"execution HIGH → LOW",
				"- HIGH shell runs a shell",
				"networking LOW → HIGH",
				"+ HIGH connect connects",
				"AF_INET",
			},
			absent: []string{"/bin/sh", "binds a port", "calls system"},
		},
		{
			name: "only added behaviors show namespace risk without a transition",
			fr: &malcontent.FileReport{
				Path:      "/bin/new",
				RiskScore: 3,
				RiskLevel: report.LevelHIGH,
				Behaviors: []*malcontent.Behavior{
					{ID: "crypto/aes", Description: "uses AES", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
				},
			},
			want:   []string{"Changed (1 added, 0 removed): /bin/new HIGH", "cryptography HIGH", "+ HIGH aes uses AES"},
			absent: []string{"→"},
		},
		{
			name: "single namespace whose risk rose shows the transition",
			fr: &malcontent.FileReport{
				Path:      "/bin/one",
				RiskScore: 3,
				RiskLevel: report.LevelHIGH,
				Behaviors: []*malcontent.Behavior{
					{ID: "net/bind", Description: "binds a port", RiskScore: 1, RiskLevel: report.LevelLOW},
					{ID: "net/connect", Description: "connects", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
				},
			},
			want:   []string{"Changed (1 added, 0 removed): /bin/one HIGH", "networking LOW → HIGH", "+ HIGH connect connects"},
			absent: []string{"binds a port"},
		},
		{
			name: "harmless unchanged behaviors do not mark other namespaces as changed",
			fr: &malcontent.FileReport{
				Path:      "/bin/new",
				RiskScore: 3,
				RiskLevel: report.LevelHIGH,
				Behaviors: []*malcontent.Behavior{
					{ID: "net/ping", Description: "pings hosts", RiskScore: 0, RiskLevel: report.LevelNONE},
					{ID: "crypto/aes", Description: "uses AES", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
				},
			},
			want:   []string{"Changed (1 added, 0 removed): /bin/new HIGH", "cryptography HIGH", "+ HIGH aes uses AES", "networking NONE"},
			absent: []string{"→", "pings hosts"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := teaSummary(t, tt.fr)
			if !renderIndexOrder(got, tt.want...) {
				t.Errorf("renderFileSummaryTea output: got = %q, want in order %q", got, tt.want)
			}
			for _, a := range tt.absent {
				if strings.Contains(got, a) {
					t.Errorf("renderFileSummaryTea output: got %q in %q, want = absent", a, got)
				}
			}
		})
	}
}

func TestRenderFileSummaryTeaWritesNothing(t *testing.T) {
	t.Parallel()
	behaviors := []*malcontent.Behavior{{ID: "net/connect", Description: "connects", RiskScore: 3, RiskLevel: report.LevelHIGH}}

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		fr := &malcontent.FileReport{Path: "/bin/x", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: behaviors}
		renderFileSummaryTea(renderCanceledContext(t), fr, &buf, tableConfig{Title: "/bin/x"})
		if buf.Len() != 0 {
			t.Errorf("renderFileSummaryTea output: got = %q, want = empty", buf.String())
		}
	})
	t.Run("skipped report", func(t *testing.T) {
		t.Parallel()
		fr := &malcontent.FileReport{Path: "/bin/x", Skipped: "too large", Behaviors: behaviors}
		if got := teaSummary(t, fr); got != "" {
			t.Errorf("renderFileSummaryTea output: got = %q, want = empty", got)
		}
	})
}

func TestRenderFileSummaryTeaWrapsLongEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		evidence string
		wantRun  int
	}{
		{name: "70-byte evidence stays on one line", evidence: strings.Repeat("q", 70), wantRun: 70},
		{name: "71-byte evidence wraps after 70 bytes", evidence: strings.Repeat("q", 71), wantRun: 70},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fr := &malcontent.FileReport{
				Path:      "/bin/tool",
				RiskScore: 3,
				RiskLevel: report.LevelHIGH,
				Behaviors: []*malcontent.Behavior{{ID: "net/connect", Description: "connects", MatchStrings: []string{tt.evidence}, RiskScore: 3, RiskLevel: report.LevelHIGH}},
			}
			var buf bytes.Buffer
			renderFileSummaryTea(t.Context(), fr, &buf, tableConfig{Title: fr.Path})
			got := renderStripANSI(buf.String())
			longest, run := 0, 0
			for _, r := range got {
				if r != 'q' {
					run = 0
					continue
				}
				run++
				longest = max(longest, run)
			}
			if longest != tt.wantRun {
				t.Errorf("longest evidence run: got = %d, want = %d in %q", longest, tt.wantRun, got)
			}
			if n := strings.Count(got, "q"); n != len(tt.evidence) {
				t.Errorf("evidence bytes shown: got = %d, want = %d", n, len(tt.evidence))
			}
		})
	}
}
