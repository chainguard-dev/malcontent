// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
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
	// Most strings are printable ASCII without surrounding spaces, which every
	// step below returns unchanged. NUL is not printable, so excepting it
	// excepts nothing more.
	if isPlainASCII(s, 0) && (s == "" || (s[0] != ' ' && s[len(s)-1] != ' ')) {
		return s
	}
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

// isPlainASCII reports whether every byte of s is printable ASCII (0x20
// through 0x7e) other than except.
func isPlainASCII(s string, except byte) bool {
	for i := range len(s) {
		if c := s[i]; c < 0x20 || c > 0x7e || c == except {
			return false
		}
	}
	return true
}

// isBiDiControl reports whether r is a Unicode Bidi_Control character: an
// embedding, override, isolate, or mark, such as U+202E or U+061C, which can
// make displayed text read differently from its bytes.
func isBiDiControl(r rune) bool {
	return unicode.Is(unicode.Bidi_Control, r)
}

// sanitizeTerminal makes untrusted text from scanned files or report files
// safe to print to a terminal. Like sanitizeUTF8, it replaces invalid UTF-8
// with U+FFFD and drops BiDi controls. It also replaces C0 controls (including
// tab and newline), DEL, and C1 controls, which terminals act on by moving the
// cursor, setting the window title, or opening hyperlinks, and the other
// invisible format characters, such as U+200B, with the visible escapes
// strconv.Quote uses, such as \x1b, \r, and \u009b. A backslash becomes \\
// so an escape spelled out in the input reads differently from an escaped
// control character. Other printable text is unchanged.
func sanitizeTerminal(s string) string {
	// Printable ASCII other than a backslash passes through unchanged.
	if isPlainASCII(s, '\\') {
		return s
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, string(utf8.RuneError))
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isBiDiControl(r) {
			continue
		}
		if r == '\\' {
			b.WriteString(`\\`)
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r) {
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
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

// sanitizeReport prepares r for serialization in place: it drops the
// absolute paths and sanitizes the text fields that come from scanned files
// or report files.
func sanitizeReport(r *malcontent.FileReport) {
	r.ArchiveRoot = ""
	r.FullPath = ""
	r.Path = sanitizeUTF8(r.Path)
	r.PreviousPath = sanitizeUTF8(r.PreviousPath)
	r.PreviousRelPath = sanitizeUTF8(r.PreviousRelPath)

	for _, b := range r.Behaviors {
		if b != nil {
			b.ID = sanitizeUTF8(b.ID)
			b.Description = sanitizeUTF8(b.Description)
		}
	}
}

// uniqueKeys returns the sanitizeUTF8 form of each of raw, kept distinct so
// that no report is lost when distinct keys sanitize alike. Of the raw keys
// that sanitize to the same key, the one sanitizing leaves unchanged keeps
// it, or else the first in raw does. The others, in the order of raw, get
// the suffix " (2)", " (3)", and so on: the lowest number that gives a key
// that neither sanitizes from raw nor was given before. The result depends
// only on raw and its order.
func uniqueKeys(raw []string) []string {
	keys := make([]string, len(raw))
	// owner maps each key in use to the index of the entry that has it.
	owner := make(map[string]int, len(raw))
	for i, r := range raw {
		k := sanitizeUTF8(r)
		keys[i] = k
		if j, taken := owner[k]; !taken || (r == k && raw[j] != k) {
			owner[k] = i
		}
	}
	if len(owner) == len(raw) {
		return keys
	}

	// next holds the next suffix number worth trying for a key.
	next := map[string]int{}
	for i, k := range keys {
		if owner[k] == i {
			continue
		}
		n := max(next[k], 2)
		for {
			suffixed := k + " (" + strconv.Itoa(n) + ")"
			if _, taken := owner[suffixed]; !taken {
				owner[suffixed] = i
				keys[i] = suffixed
				break
			}
			n++
		}
		next[k] = n + 1
	}
	return keys
}

// sanitizedDiff returns d for serialization: its reports sanitized in place
// as scan reports are, under keys made distinct by uniqueKeys in each of its
// maps. It stops with the context's error when ctx is canceled.
func sanitizedDiff(ctx context.Context, d *malcontent.DiffReport) (*malcontent.DiffReport, error) {
	if d == nil {
		return nil, nil
	}
	added, err := sanitizedDiffMap(ctx, d.Added)
	if err != nil {
		return nil, err
	}
	removed, err := sanitizedDiffMap(ctx, d.Removed)
	if err != nil {
		return nil, err
	}
	modified, err := sanitizedDiffMap(ctx, d.Modified)
	if err != nil {
		return nil, err
	}
	return &malcontent.DiffReport{Added: added, Removed: removed, Modified: modified}, nil
}

// sanitizedDiffMap returns the entries of m in order, with their reports
// sanitized in place and their keys made distinct by uniqueKeys. A nil map
// stays nil, so it is still left out of the output.
func sanitizedDiffMap(ctx context.Context, m *malcontent.OrderedFileReports) (*malcontent.OrderedFileReports, error) {
	if m == nil {
		return nil, nil
	}
	raw := make([]string, 0, m.Len())
	reports := make([]*malcontent.FileReport, 0, m.Len())
	for p := m.Oldest(); p != nil; p = p.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.Value != nil {
			sanitizeReport(p.Value)
		}
		raw = append(raw, p.Key)
		reports = append(reports, p.Value)
	}
	out := new(malcontent.OrderedFileReports)
	for i, k := range uniqueKeys(raw) {
		out.Set(k, reports[i])
	}
	return out, nil
}

// diffCounts returns how many of bs are marked added and how many removed.
func diffCounts(bs []*malcontent.Behavior) (added, removed int) {
	for _, bh := range bs {
		if bh.DiffAdded {
			added++
		}
		if bh.DiffRemoved {
			removed++
		}
	}
	return added, removed
}

// diffTitle returns the title of a modified file in a diff without its risk
// levels, with its paths escaped by escape: "Moved (a added, r removed):
// previous -> path" for a file found under a new path, and "Changed (a
// added, r removed): path" otherwise.
func diffTitle(fr *malcontent.FileReport, added, removed int, escape func(string) string) string {
	if fr.PreviousPath != "" {
		return fmt.Sprintf("Moved (%d added, %d removed): %s -> %s", added, removed, escape(fr.PreviousPath), escape(fr.Path))
	}
	return fmt.Sprintf("Changed (%d added, %d removed): %s", added, removed, escape(fr.Path))
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
