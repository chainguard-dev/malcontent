// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/fatih/color"
	"github.com/puzpuzpuz/xsync/v4"
)

var updateGoldens = flag.Bool("update", false, "rewrite the golden files under testdata/golden")

// goldenWidths are the terminal widths the golden files render against: the
// narrowest the renderers allow and the default.
var goldenWidths = []int{75, 160}

const (
	// goldenWideSweep is the longest evidence in the escape sweep of the
	// renderers that measure lines against the width. It passes the widest
	// of goldenWidths.
	goldenWideSweep = 170
	// goldenShortSweep is the longest evidence in the escape sweep of the
	// other renderers, which only need each description once with evidence
	// long enough to show.
	goldenShortSweep = 4
)

// checkGolden compares got with the golden file testdata/golden/name and
// reports the first line where they differ. With -update, it writes got to
// the file instead.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *updateGoldens {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("MkdirAll(%q): got err = %v, want = nil", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("WriteFile(%q): got err = %v, want = nil", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): got err = %v, want = nil; run the test with -update to create it", path, err)
	}
	if bytes.Equal(got, want) {
		return
	}
	gotLines := strings.Split(string(got), "\n")
	wantLines := strings.Split(string(want), "\n")
	i := 0
	for i < len(gotLines) && i < len(wantLines) && gotLines[i] == wantLines[i] {
		i++
	}
	t.Errorf("%s: output differs at line %d of %d (want %d lines):\ngot  = %s\nwant = %s\nrun the test with -update if the change is intended",
		path, i+1, len(gotLines), len(wantLines), goldenLine(gotLines, i), goldenLine(wantLines, i))
}

// goldenLine quotes line i of lines, or notes that lines ends before it.
func goldenLine(lines []string, i int) string {
	if i >= len(lines) {
		return "(no such line)"
	}
	return strconv.Quote(lines[i])
}

// goldenScanReports returns fresh file reports that reach every branch of the
// text renderers: each risk level and some outside the known ones, rule
// authors, descriptions with " - " and ". ", short, filtered, and long
// evidence, control and BiDi characters, namespaces whose long names share a
// length, and an escape sweep whose evidence runs up to sweep bytes.
func goldenScanReports(sweep int) []*malcontent.FileReport {
	long := "https://example.com/" + strings.Repeat("a", 180)
	return []*malcontent.FileReport{
		{
			Path:      "/usr/bin/tool",
			SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Size:      4096,
			RiskScore: 4,
			RiskLevel: report.LevelCRITICAL,
			Syscalls:  []string{"connect", "execve"},
			Meta:      map[string]string{"format": "elf", "arch": "amd64"},
			Behaviors: []*malcontent.Behavior{
				{ID: "net/socket/connect", Description: "connects to a remote host - via TCP", MatchStrings: []string{"connect", "AF_INET", "ab"}, RiskScore: 2, RiskLevel: report.LevelMEDIUM, RuleName: "net_connect", RuleAuthor: "Alice", RuleURL: "https://r/connect"},
				{ID: "c2/addr/url", Description: "contains a hardcoded URL. Often benign", MatchStrings: []string{long, "http://x.example/a|b"}, RiskScore: 3, RiskLevel: report.LevelHIGH, RuleName: "url", ReferenceURL: "https://ref.example/url"},
				{ID: "exec/shell", Description: "runs shell commands", MatchStrings: []string{"/bin/sh", "sh -c", "$sh_var"}, RiskScore: 4, RiskLevel: report.LevelCRITICAL, RuleName: "shell", RuleAuthor: "Bob", RuleAuthorURL: "https://bob.example"},
				{ID: "fs/file/read", Description: "reads files", RiskScore: 1, RiskLevel: report.LevelLOW, RuleName: "read"},
				{ID: "anti-static/obfuscation/hex", Description: "hex-encoded payload", MatchStrings: []string{`\x41\x42`, "evil\x1b[2Jpayload\ttab", "naïve 😈 \u202Ertl"}, RiskScore: 3, RiskLevel: report.LevelHIGH, RuleName: "hex"},
				{ID: "sus/text", MatchStrings: []string{"password", "credential"}, RiskScore: 2, RiskLevel: report.LevelMEDIUM, RuleAuthor: "Carol", RuleName: "sus"},
				{ID: "nonamespace", Description: "no slash in the ID", MatchStrings: []string{"abcd", "abcde"}, RiskScore: 0, RiskLevel: report.LevelNONE, RuleName: "nons"},
				{ID: "hw/cpu", Description: "reads cpu info", MatchStrings: []string{"cpuinfo"}, RiskScore: 5, RiskLevel: "EXTREME", RuleName: "cpu"},
				{ID: "os/env/get", Description: "calls getenv", MatchStrings: []string{"getenv", "setenv"}, RiskScore: -1, RuleName: "env"},
				{ID: "net/dns", Description: "resolves names", MatchStrings: []string{"gethostbyname"}, RiskScore: 1, RiskLevel: report.LevelLOW, RuleName: "dns"},
				{ID: "collect/files", Description: "collects files", MatchStrings: []string{"glob"}, RiskScore: 2, RiskLevel: "MED", RuleName: "collect"},
				{ID: "malware/family", Description: "names a family", MatchStrings: []string{"family"}, RiskScore: 4, RiskLevel: levelCRIT, RuleName: "family"},
				{ID: "fs/file/write", Description: "writes files - often", MatchStrings: []string{"fwrite", "fopen"}, RiskScore: 2, RiskLevel: report.LevelMEDIUM, RuleName: "write", RuleAuthor: "Dee"},
			},
		},
		{
			Path:      "/tmp/naïve 😈\x1b]0;title\x07\\back\u202Eslash",
			RiskScore: 1,
			RiskLevel: report.LevelLOW,
			Behaviors: []*malcontent.Behavior{
				{ID: "fs/write", Description: "writes files", MatchStrings: []string{"fopen"}, RiskScore: 1, RiskLevel: report.LevelLOW, RuleName: "write"},
			},
		},
		{Path: "/bin/empty"},
		{Path: "/bin/skipped", Skipped: "data file", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{{ID: "net/connect", RiskScore: 3}}},
		goldenEscapeSweep(sweep),
	}
}

// goldenEscapeSweep returns a report with a behavior for every evidence
// length from 1 to longest bytes under each of several descriptions. Some
// descriptions end with an incomplete escape sequence the evidence can
// complete, so line measurement must treat the description and the evidence
// as one line. Sweeping past the widest of goldenWidths reaches every point
// where evidence moves to a line of its own or gets truncated.
func goldenEscapeSweep(longest int) *malcontent.FileReport {
	fr := &malcontent.FileReport{Path: "/opt/escapes", RiskScore: 2, RiskLevel: report.LevelMEDIUM}
	variants := []struct{ desc, lead string }{
		{desc: "plain description", lead: ""},
		{desc: "ends in a partial escape \x1b[", lead: "1m"},
		{desc: "ends in an escape byte \x1b", lead: "[0m"},
		{desc: "has a whole escape \x1b[31mred\x1b[0m and \x1b[10Gcolumn", lead: "2;3G"},
	}
	for v, variant := range variants {
		for n := 1; n <= longest; n++ {
			fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{
				ID:           fmt.Sprintf("evasion/sweep-%d-%d", v, n),
				Description:  variant.desc,
				MatchStrings: []string{variant.lead + strings.Repeat("q", n)},
				RiskScore:    2,
				RiskLevel:    report.LevelMEDIUM,
				RuleName:     fmt.Sprintf("sweep_%d_%d", v, n),
			})
		}
	}
	return fr
}

// goldenDiffReport returns a fresh diff with deleted, added, changed, moved,
// and unchanged files and risk changes in both directions.
func goldenDiffReport() *malcontent.Report {
	long := strings.Repeat("evidence-", 30)
	return &malcontent.Report{Diff: renderDiff(
		[]*malcontent.FileReport{
			{Path: "/old/empty"},
			{Path: "/old/tool", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{
				{ID: "net/connect", Description: "connects", MatchStrings: []string{"AF_INET"}, RiskScore: 3, RiskLevel: report.LevelHIGH, RuleURL: "https://r/connect"},
				{ID: "fs/read", Description: "reads files", RiskScore: 1, RiskLevel: report.LevelLOW, RuleURL: "https://r/read"},
			}},
		},
		[]*malcontent.FileReport{
			{Path: "/new/tool\x1b[2J", RiskScore: 2, RiskLevel: report.LevelMEDIUM, Behaviors: []*malcontent.Behavior{
				{ID: "fs/write", Description: "writes files", MatchStrings: []string{long}, RiskScore: 2, RiskLevel: report.LevelMEDIUM, RuleURL: "https://r/write"},
			}},
		},
		[]*malcontent.FileReport{
			{Path: "/mod/changed", RiskScore: 3, RiskLevel: report.LevelHIGH, PreviousRiskScore: 1, PreviousRiskLevel: report.LevelLOW, Behaviors: []*malcontent.Behavior{
				{ID: "net/bind", Description: "binds a port", RiskScore: 1, RiskLevel: report.LevelLOW, RuleURL: "https://r/bind"},
				{ID: "exec/shell", Description: "runs a shell - quickly", MatchStrings: []string{"/bin/sh", long}, RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true, RuleAuthor: "Dee", RuleURL: "https://r/shell"},
				{ID: "fs/read", Description: "reads files", MatchStrings: []string{"fopen"}, RiskScore: 1, RiskLevel: report.LevelLOW, DiffRemoved: true, RuleURL: "https://r/read"},
				{ID: "crypto/aes", Description: "uses AES", RiskScore: 2, RiskLevel: report.LevelMEDIUM, DiffAdded: true, DiffRemoved: true, RuleURL: "https://r/aes"},
				{ID: "c2/beacon", Description: "beacons", RiskScore: 0, RiskLevel: report.LevelNONE, DiffRemoved: true, RuleURL: "https://r/beacon"},
			}},
			{Path: "/mod/new-name", PreviousPath: "/mod/old-name", RiskScore: 2, RiskLevel: report.LevelMEDIUM, PreviousRiskScore: 2, PreviousRiskLevel: report.LevelMEDIUM, Behaviors: []*malcontent.Behavior{
				{ID: "crypto/rc4", Description: "uses RC4", MatchStrings: []string{"rc4_init"}, RiskScore: 2, RiskLevel: report.LevelMEDIUM, DiffAdded: true, RuleURL: "https://r/rc4"},
			}},
			{Path: "/mod/same", RiskScore: 1, RiskLevel: report.LevelLOW, Behaviors: []*malcontent.Behavior{
				{ID: "net/listen", Description: "listens", RiskScore: 1, RiskLevel: report.LevelLOW, RuleURL: "https://r/listen"},
			}},
			{Path: "/mod/lowered", RiskScore: 1, RiskLevel: report.LevelLOW, PreviousRiskScore: 3, PreviousRiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{
				{ID: "net/connect", Description: "connects", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffRemoved: true, RuleURL: "https://r/connect"},
				{ID: "net/bind", Description: "binds a port", RiskScore: 1, RiskLevel: report.LevelLOW, RuleURL: "https://r/bind"},
			}},
		},
	)}
}

// goldenNilBehaviorReport returns a fresh scan report whose file holds a nil
// behavior, which serialization tolerates and statistics do not.
func goldenNilBehaviorReport() *malcontent.Report {
	files := xsync.NewMap[string, *malcontent.FileReport]()
	files.Store("/bin/nil", &malcontent.FileReport{
		Path:      "/bin/nil",
		RiskScore: 1,
		RiskLevel: report.LevelLOW,
		Behaviors: []*malcontent.Behavior{nil, {ID: "net/connect", RiskScore: 1, RiskLevel: report.LevelLOW}, nil},
	})
	return &malcontent.Report{Files: files}
}

// goldenScanReport returns a fresh scan report whose keys need sanitizing or
// escaping, along with an empty key, a nil report, and a skipped report. Two
// keys become equal once sanitized. The serializers keep whichever of their
// reports they range over last, and the range order of the map changes from
// run to run, so both reports hold the same content.
func goldenScanReport() *malcontent.Report {
	files := xsync.NewMap[string, *malcontent.FileReport]()
	for _, fr := range goldenScanReports(goldenShortSweep) {
		files.Store(fr.Path, fr)
	}
	keyed := []struct{ key, path string }{
		{key: "<script>&amp;\u2028\u2029", path: "/html"},
		{key: "quote\"back\\slash\ttab", path: "/escapes"},
		{key: "\xffinvalid\xfe", path: "/invalid"},
		{key: "bidi\u202Ekey", path: "/bidi"},
		{key: "dup ", path: "/dup"},
		{key: "dup\n", path: "/dup"},
		{key: "", path: "/empty-key"},
		{key: " trimmed\r\n", path: "/trimmed"},
	}
	for _, k := range keyed {
		files.Store(k.key, &malcontent.FileReport{
			Path:      k.path + " \n",
			RiskScore: 2,
			RiskLevel: report.LevelMEDIUM,
			Behaviors: []*malcontent.Behavior{
				{ID: "net/connect\n", Description: "  connects\u202E ", MatchStrings: []string{"<b>&", "\u2028"}, RiskScore: 2, RiskLevel: report.LevelMEDIUM},
			},
			ArchiveRoot: "/archive",
			FullPath:    "/archive" + k.path,
		})
	}
	files.Store("nil-report", nil)
	return &malcontent.Report{Files: files}
}

// goldenManyFiles returns a fresh scan report with n files, enough to split
// the JSON "Files" object across encoding chunks, with keys that need
// escaping spread through the sort order.
func goldenManyFiles(n int) *malcontent.Report {
	files := xsync.NewMap[string, *malcontent.FileReport]()
	for i := range n {
		key := fmt.Sprintf("/many/file-%04d", i)
		switch i % 10 {
		case 3:
			key += "<&>"
		case 7:
			key += "\u2028\"quoted\""
		}
		fr := &malcontent.FileReport{Path: key, SHA256: fmt.Sprintf("%064x", i), Size: int64(i), RiskScore: i % 5, RiskLevel: riskLevels[i%5]}
		for j := range i % 6 {
			fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{
				ID:           fmt.Sprintf("ns%d/behavior-%d", j%3, j),
				Description:  "does something & more <here>",
				MatchStrings: []string{fmt.Sprintf("match-%d-%d", i, j)},
				RiskScore:    j % 5,
				RiskLevel:    riskLevels[j%5],
				RuleURL:      fmt.Sprintf("https://r/%d", j),
			})
		}
		if i%11 == 0 {
			fr.Skipped = "too large"
		}
		files.Store(key, fr)
	}
	return &malcontent.Report{Files: files}
}

// goldenTextRenderer builds a text renderer whose output golden files record.
type goldenTextRenderer struct {
	// golden names the golden file of the File output, without the color
	// suffix and the extension.
	golden string
	// diffGolden names the golden file of the diff output in the same way. It
	// is empty for renderers that print no diffs.
	diffGolden string
	ext        string
	// sweep is the longest evidence in the escape sweep of the File output.
	sweep       int
	newRenderer func(w io.Writer) malcontent.Renderer
}

// goldenTextRenderers returns the text renderers the golden files cover, the
// terminal renderers once for each of goldenWidths.
func goldenTextRenderers() []goldenTextRenderer {
	rs := make([]goldenTextRenderer, 0, 2*len(goldenWidths)+3)
	for _, width := range goldenWidths {
		rs = append(rs,
			goldenTextRenderer{
				golden:     fmt.Sprintf("terminal_w%d", width),
				diffGolden: fmt.Sprintf("terminal_diff_w%d", width),
				ext:        ".txt",
				sweep:      goldenWideSweep,
				newRenderer: func(w io.Writer) malcontent.Renderer {
					return &Terminal{out: blockWriter{w: w}, width: width}
				},
			},
			goldenTextRenderer{
				golden: fmt.Sprintf("terminal_brief_w%d", width),
				ext:    ".txt",
				sweep:  goldenWideSweep,
				newRenderer: func(w io.Writer) malcontent.Renderer {
					return &TerminalBrief{out: blockWriter{w: w}, width: width}
				},
			},
		)
	}
	return append(rs,
		goldenTextRenderer{
			golden:      "simple",
			diffGolden:  "simple_diff",
			ext:         ".txt",
			sweep:       goldenShortSweep,
			newRenderer: func(w io.Writer) malcontent.Renderer { return NewSimple(w) },
		},
		goldenTextRenderer{
			golden:      "strings",
			ext:         ".txt",
			sweep:       goldenShortSweep,
			newRenderer: func(w io.Writer) malcontent.Renderer { return NewStringMatches(w) },
		},
		goldenTextRenderer{
			golden:      "markdown",
			diffGolden:  "markdown_diff",
			ext:         ".md",
			sweep:       goldenShortSweep,
			newRenderer: func(w io.Writer) malcontent.Renderer { return NewMarkdown(w) },
		},
	)
}

// TestTextRenderersMatchGoldens compares the File and diff output of the
// text renderers with the golden files, with color off and on. It sets
// color.NoColor, so neither it nor its subtests run in parallel.
func TestTextRenderersMatchGoldens(t *testing.T) {
	saved := color.NoColor
	t.Cleanup(func() { color.NoColor = saved })

	modes := []struct {
		name    string
		suffix  string
		noColor bool
	}{
		{name: "color off", suffix: "", noColor: true},
		{name: "color on", suffix: "_color", noColor: false},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			if !m.noColor && os.Getenv("NO_COLOR") != "" {
				t.Skip("NO_COLOR is set, so fatih/color writes no escape sequences")
			}
			color.NoColor = m.noColor
			for _, r := range goldenTextRenderers() {
				t.Run(r.golden, func(t *testing.T) {
					var b bytes.Buffer
					rr := r.newRenderer(&b)
					// Each renderer gets its own reports: the strings renderer sorts behaviors in place.
					for _, fr := range goldenScanReports(r.sweep) {
						if err := rr.File(t.Context(), fr); err != nil {
							t.Fatalf("File(%q): got err = %v, want = nil", fr.Path, err)
						}
					}
					checkGolden(t, r.golden+m.suffix+r.ext, b.Bytes())
				})
				if r.diffGolden == "" {
					continue
				}
				t.Run(r.diffGolden, func(t *testing.T) {
					var b bytes.Buffer
					if err := r.newRenderer(&b).Full(t.Context(), &malcontent.Config{}, goldenDiffReport()); err != nil {
						t.Fatalf("Full: got err = %v, want = nil", err)
					}
					checkGolden(t, r.diffGolden+m.suffix+r.ext, b.Bytes())
				})
			}
		})
	}
}

// TestInteractiveSummaryMatchesGolden compares the file summaries of the
// interactive viewer with the golden file. lipgloss picks its color profile
// from the terminal on standard output, so the comparison drops the escape
// sequences colors add and checks the text and layout.
func TestInteractiveSummaryMatchesGolden(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	for _, fr := range goldenScanReports(goldenShortSweep) {
		renderFileSummaryTea(t.Context(), fr, &b)
	}
	diff := goldenDiffReport().Diff
	for m := diff.Modified.Oldest(); m != nil; m = m.Next() {
		renderFileSummaryTea(t.Context(), m.Value, &b)
	}
	checkGolden(t, "interactive_summary.txt", []byte(renderStripANSI(b.String())))
}

// TestSerializedRenderersMatchGoldens compares the JSON and YAML documents of
// scan and diff reports with the golden files.
func TestSerializedRenderersMatchGoldens(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		golden string
		cfg    *malcontent.Config
		rep    func() *malcontent.Report
	}{
		{name: "empty report with stats", golden: "empty_stats", cfg: &malcontent.Config{Stats: true}, rep: func() *malcontent.Report {
			return &malcontent.Report{Files: xsync.NewMap[string, *malcontent.FileReport]()}
		}},
		{name: "report without files", golden: "no_files", rep: func() *malcontent.Report { return &malcontent.Report{} }},
		{name: "report with a nil behavior", golden: "nil_behavior", rep: goldenNilBehaviorReport},
		{name: "scan report", golden: "scan", rep: goldenScanReport},
		{name: "scan report with stats", golden: "scan_stats", cfg: &malcontent.Config{Stats: true}, rep: goldenScanReport},
		{name: "scan report with scan-mode stats", golden: "scan_stats_scan_mode", cfg: &malcontent.Config{Stats: true, Scan: true}, rep: goldenScanReport},
		{name: "a chunk's worth of files", golden: "files_one_chunk", rep: func() *malcontent.Report { return goldenManyFiles(jsonFilesPerChunk) }},
		{name: "a chunk's worth of files and one more", golden: "files_one_chunk_plus_one", rep: func() *malcontent.Report { return goldenManyFiles(jsonFilesPerChunk + 1) }},
		{name: "files across several chunks with stats", golden: "files_chunks_stats", cfg: &malcontent.Config{Stats: true}, rep: func() *malcontent.Report {
			return goldenManyFiles(3*jsonFilesPerChunk + 5)
		}},
		{name: "diff report with stats", golden: "diff_stats", cfg: &malcontent.Config{Stats: true}, rep: goldenDiffReport},
		{name: "diff report with files", golden: "diff_files", rep: func() *malcontent.Report {
			rep := goldenScanReport()
			rep.Diff = goldenDiffReport().Diff
			return rep
		}},
	}
	formats := []struct {
		name   string
		ext    string
		render func(ctx context.Context, w io.Writer, c *malcontent.Config, rep *malcontent.Report) error
	}{
		{
			name: "json",
			ext:  ".json",
			render: func(ctx context.Context, w io.Writer, c *malcontent.Config, rep *malcontent.Report) error {
				return NewJSON(w).Full(ctx, c, rep)
			},
		},
		{
			name: "yaml",
			ext:  ".yaml",
			render: func(ctx context.Context, w io.Writer, c *malcontent.Config, rep *malcontent.Report) error {
				return NewYAML(w).Full(ctx, c, rep)
			},
		},
	}
	for _, f := range formats {
		for _, tt := range cases {
			t.Run(f.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				var b bytes.Buffer
				if err := f.render(t.Context(), &b, tt.cfg, tt.rep()); err != nil {
					t.Fatalf("Full: got err = %v, want = nil", err)
				}
				checkGolden(t, f.name+"_"+tt.golden+f.ext, b.Bytes())
			})
		}
	}
}
