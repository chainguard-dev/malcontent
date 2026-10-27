// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"cmp"
	"context"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"golang.org/x/term"
)

type KeyedBehavior struct {
	Key      string
	Behavior *malcontent.Behavior
}

type tableConfig struct {
	Title        string
	ShowTitle    bool
	DiffRemoved  bool
	DiffAdded    bool
	NoDiff       bool
	SkipAdded    bool
	SkipNoDiff   bool
	SkipRemoved  bool
	SkipExisting bool
}

// behaviorIndent indents a behavior line under its namespace line.
const behaviorIndent = "      "

// Terminal renders each file's behaviors, grouped by namespace, as the scan
// reports them. It is safe for concurrent use: each File call writes its
// output with a single Write.
type Terminal struct {
	out blockWriter
	// width is the terminal width that long evidence wraps against, measured once.
	width int
}

func NewTerminal(w io.Writer) *Terminal {
	return &Terminal{out: blockWriter{w: w}, width: suggestedWidth()}
}

func darkBrackets(s string) string {
	hb := currentPalette().hiBlack
	return hb.on + "[" + hb.off + s + hb.on + "]" + hb.off
}

// riskInColor returns level, escaped by sanitizeTerminal, in its own color.
func riskInColor(level string) string {
	return riskColor(level, sanitizeTerminal(level))
}

func riskColor(level string, text string) string {
	return currentPalette().risk(level).sprint(text)
}

func ShortRisk(s string) string {
	switch s {
	case report.LevelCRITICAL:
		return levelCRIT
	case report.LevelMEDIUM:
		return "MED"
	case report.LevelHIGH, report.LevelLOW, report.LevelNONE:
		return s
	default:
		return s
	}
}

func (r *Terminal) Name() string { return "Terminal" }

func (r *Terminal) Scanning(_ context.Context, path string) {
	r.out.scanning(path)
}

func (r *Terminal) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr.Skipped != "" || len(fr.Behaviors) == 0 {
		return nil
	}

	p := currentPalette()
	b := getBuffer()
	defer putBuffer(b)

	writeSummaryHeader(b, fr.RiskScore)
	b.WriteString(sanitizeTerminal(fr.Path))
	b.WriteByte(' ')
	p.hiBlack.wrap(b, "[")
	p.risk(fr.RiskLevel).wrap(b, sanitizeTerminal(fr.RiskLevel))
	p.hiBlack.wrap(b, "]")
	b.WriteByte('\n')
	writeSummaryBody(b, p, fr, r.width)
	return r.out.write(b.Bytes())
}

func (r *Terminal) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// guard against nil reports
	// Non-diff files are handled on the fly by File()
	if rep == nil || rep.Diff == nil {
		return nil
	}

	b := getBuffer()
	defer putBuffer(b)

	// write renders fr under title and writes it, stopping when ctx is canceled.
	write := func(fr *malcontent.FileReport, title string) error {
		if err := renderFileSummary(ctx, b, fr, title, r.width); err != nil {
			return err
		}
		return r.out.flush(b)
	}

	for _, section := range []struct {
		files *malcontent.OrderedFileReports
		label string
	}{{rep.Diff.Removed, "Deleted: "}, {rep.Diff.Added, "Added: "}} {
		for p := section.files.Oldest(); p != nil; p = p.Next() {
			fr := p.Value
			if len(fr.Behaviors) == 0 {
				continue
			}
			title := riskColor(fr.RiskLevel, section.label+sanitizeTerminal(p.Key)+" "+darkBrackets(riskInColor(fr.RiskLevel)))
			if err := write(fr, title); err != nil {
				return err
			}
		}
	}

	for p := rep.Diff.Modified.Oldest(); p != nil; p = p.Next() {
		fr := p.Value
		added, removed := diffCounts(fr.Behaviors)
		if added == 0 && removed == 0 {
			continue
		}

		// A moved file's title takes the color of its previous risk.
		level := fr.RiskLevel
		if fr.PreviousPath != "" {
			level = fr.PreviousRiskLevel
		}
		title := riskColor(level, diffTitle(fr, added, removed, sanitizeTerminal))
		if fr.RiskScore != fr.PreviousRiskScore {
			title += " " + darkBrackets(riskInColor(fr.PreviousRiskLevel)+" "+currentPalette().hiWhite.sprint("→")+" "+riskInColor(fr.RiskLevel))
		}
		if err := write(fr, title); err != nil {
			return err
		}
	}

	return nil
}

// generate a good looking evidence string.
func evidenceString(ms []string, desc string) string {
	var b strings.Builder
	var first string
	n := 0
	for _, m := range ms {
		if len(m) <= 2 || strings.Contains(desc, m) {
			continue
		}
		switch n {
		case 0:
			first = m
		case 1:
			b.WriteString(first)
			b.WriteString(", ")
			b.WriteString(m)
		default:
			b.WriteString(", ")
			b.WriteString(m)
		}
		n++
	}
	if n <= 1 {
		return first
	}
	return b.String()
}

// convert namespace to a long name.
func nsLongName(s string) string {
	switch s {
	case "c2":
		return "command & control"
	case "collect":
		return "collection"
	case "crypto":
		return "cryptography"
	case "discover":
		return "discovery"
	case "exfil":
		return "exfiltration"
	case "exec":
		return "execution"
	case "fs":
		return "filesystem"
	case "hw":
		return "hardware"
	case "net":
		return "networking"
	case "os":
		return "operating-system"
	case "3P":
		return "third-party"
	case "sus":
		return "suspicious text"
	case "persist":
		return "persistence"
	case "malware":
		return "MALWARE FAMILY"
	default:
		return s
	}
}

// split rule into namespace + resource/technique.
func splitRuleID(s string) (string, string) {
	id, rest, _ := strings.Cut(s, "/")
	return id, rest
}

// suggestedWidth calculates a maximum terminal width to render against: the
// width of the terminal on standard input, at least 75 columns, or 160 when
// standard input has no terminal size.
func suggestedWidth() int {
	width, _, err := term.GetSize(0)
	if err != nil {
		return 160
	}
	return max(width, 75)
}

// truncateLine shortens the line b holds from start to its end when it is
// longer than width bytes: it keeps at most the first width-1 bytes, ending
// on a character boundary, and appends an ellipsis.
func truncateLine(b *bytes.Buffer, start, width int) {
	if b.Len()-start <= width {
		return
	}
	cut := start + width - 1
	for cut > start && !utf8.RuneStart(b.Bytes()[cut]) {
		cut--
	}
	b.Truncate(cut)
	b.WriteString("…")
}

// ansiLineLength determines the length of a line, even if it has ANSI codes:
// it counts the bytes of s outside SGR and cursor-column sequences, which are
// ESC [, any digits and semicolons, and a final m or G.
func ansiLineLength[T ~string | ~[]byte](s T) int {
	n := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] != 0x1b || i+1 == len(s) || s[i+1] != '[' {
			continue
		}
		j := i + 2
		for j < len(s) && (s[j] == ';' || (s[j] >= '0' && s[j] <= '9')) {
			j++
		}
		if j < len(s) && (s[j] == 'm' || s[j] == 'G') {
			n -= j + 1 - i
			i = j
		}
	}
	return n
}

// lineLength returns the ansiLineLength of the bytes b holds from start to
// end followed by parts. It assembles that line past the end of b and then
// truncates b again, so the contents of b do not change.
func lineLength(b *bytes.Buffer, start, end int, parts ...string) int {
	mark := b.Len()
	b.Write(b.Bytes()[start:end])
	for _, s := range parts {
		b.WriteString(s)
	}
	n := ansiLineLength(b.Bytes()[mark:])
	b.Truncate(mark)
	return n
}

// renderFileSummary renders fr under title, which the caller builds, including
// any diff counts and risk transition. It writes nothing for a skipped report
// and returns the context's error, writing nothing, when ctx is canceled.
func renderFileSummary(ctx context.Context, b *bytes.Buffer, fr *malcontent.FileReport, title string, width int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if fr.Skipped != "" {
		return nil
	}

	writeSummaryHeader(b, fr.RiskScore)
	b.WriteString(title)
	b.WriteByte('\n')
	writeSummaryBody(b, currentPalette(), fr, width)
	return nil
}

// writeSummaryHeader starts the first line of a file summary, up to its title.
func writeSummaryHeader(b *bytes.Buffer, riskScore int) {
	b.WriteString("├─ ")
	b.WriteString(riskEmoji(riskScore))
	b.WriteByte(' ')
}

// nsGroup holds what a file summary prints for one namespace.
type nsGroup struct {
	ns string
	// long is nsLongName(ns), escaped by sanitizeTerminal.
	long string
	// index is the namespace's position in order of first appearance.
	index int
	// risk is the highest risk score of the behaviors listed under it, or 0.
	risk int
}

// listedBehavior reports whether a file summary lists bh. A diff lists only
// added and removed behaviors; other summaries list every behavior.
func listedBehavior(bh *malcontent.Behavior, diffMode bool) bool {
	return !diffMode || bh.DiffAdded || bh.DiffRemoved
}

// isDiffMode reports whether any of bs is marked added or removed, which
// makes a file summary show a diff.
func isDiffMode(bs []*malcontent.Behavior) bool {
	return slices.ContainsFunc(bs, func(bh *malcontent.Behavior) bool { return bh.DiffAdded || bh.DiffRemoved })
}

// writeSummaryBody writes fr's listed behaviors grouped by namespace, then
// the closing bar. Namespaces print in order of the length of their long
// names; those whose long names are the same length print in the order they
// first appear. A namespace with no listed behaviors is left out.
func writeSummaryBody(b *bytes.Buffer, p *palette, fr *malcontent.FileReport, width int) {
	diffMode := isDiffMode(fr.Behaviors)
	groups := make([]nsGroup, 0, 16)
	// groupOf holds the group of each behavior, or -1 for one not listed.
	groupOf := make([]int, 0, 64)

	for _, bh := range fr.Behaviors {
		if !listedBehavior(bh, diffMode) {
			groupOf = append(groupOf, -1)
			continue
		}
		ns, _ := splitRuleID(bh.ID)
		g := slices.IndexFunc(groups, func(x nsGroup) bool { return x.ns == ns })
		if g < 0 {
			g = len(groups)
			groups = append(groups, nsGroup{ns: ns, long: sanitizeTerminal(nsLongName(ns)), index: g})
		}
		groupOf = append(groupOf, g)
		groups[g].risk = max(groups[g].risk, bh.RiskScore)
	}

	slices.SortStableFunc(groups, func(x, y nsGroup) int {
		return cmp.Compare(len(x.long), len(y.long))
	})

	for i := range groups {
		g := &groups[i]
		writeNamespaceLine(b, p, g)
		for j, bh := range fr.Behaviors {
			if groupOf[j] == g.index {
				writeBehaviorLine(b, p, bh, diffMode, width)
			}
		}
	}
	b.WriteString("│\n")
}

// writeNamespaceLine writes the line that introduces a namespace: its long
// name and the highest risk level among the behaviors listed under it. A
// diff lists only the behaviors that changed, so the line shows no change of
// the namespace's risk.
func writeNamespaceLine(b *bytes.Buffer, p *palette, g *nsGroup) {
	level := riskLevels[g.risk]
	b.WriteString("│     ≡ ")
	b.WriteString(g.long)
	b.WriteByte(' ')
	p.hiBlack.wrap(b, "[")
	p.risk(level).wrap(b, level)
	p.hiBlack.wrap(b, "]")
	b.WriteByte('\n')
}

// writeBehaviorLine writes one listed behavior and its evidence. In diff mode
// it marks the behavior added or removed and drops the evidence of removed
// ones. Evidence that would reach width moves to a line of its own, truncated
// to width.
func writeBehaviorLine(b *bytes.Buffer, p *palette, bh *malcontent.Behavior, diffMode bool, width int) {
	pc := p.plain
	diff := " "
	if diffMode {
		if bh.DiffAdded {
			pc, diff = p.hiGreen, "+"
		}
		if bh.DiffRemoved {
			pc, diff = p.hiRed, "-"
		}
	}

	// Outside diff mode no behavior is marked removed.
	var e string
	if !bh.DiffRemoved {
		e = sanitizeTerminal(evidenceString(bh.MatchStrings, bh.Description))
	}

	_, rest := splitRuleID(bh.ID)
	rest = sanitizeTerminal(rest)
	desc, _, _ := strings.Cut(bh.Description, " - ")
	desc = sanitizeTerminal(desc)
	bullet := riskEmoji(bh.RiskScore)

	b.WriteString("│")
	b.WriteString(pc.on)
	start := b.Len()
	b.WriteString(diff)
	b.WriteString(behaviorIndent)
	if diffMode {
		b.WriteString(bullet)
		b.WriteByte(' ')
		b.WriteString(rest)
	} else {
		rs := p.risk(bh.RiskLevel)
		b.WriteString(rs.on)
		b.WriteString(bullet)
		b.WriteByte(' ')
		b.WriteString(rest)
		b.WriteString(rs.off)
	}
	b.WriteString(" — ")
	b.WriteString(desc)
	if bh.RuleAuthor != "" {
		b.WriteString(", by ")
		b.WriteString(sanitizeTerminal(bh.RuleAuthor))
	}
	end := b.Len()

	// no evidence to give
	if e == "" {
		b.WriteString(pc.off)
		b.WriteByte('\n')
		return
	}

	b.WriteString(pc.printOff)
	b.WriteString(p.hiBlack.on)
	b.WriteByte(':')
	b.WriteString(p.hiBlack.printOff)

	ev := p.evidence
	b.WriteString(pc.on)
	// Evidence of up to four bytes stays on the line. The length once
	// included the color sequences, so colored evidence always qualifies.
	if lineLength(b, start, end, ev.on, e, ev.off)+1 > width && (len(e) > 4 || ev.on != "") {
		// Two-line output for long evidence strings
		b.WriteByte('\n')
		lineStart := b.Len()
		b.WriteString("│")
		b.WriteString(diff)
		b.WriteString("         ")
		ev.wrap(b, e)
		truncateLine(b, lineStart, width)
	} else {
		// Single-line output for short evidence
		b.WriteByte(' ')
		ev.wrap(b, e)
	}
	b.WriteString(pc.off)
	b.WriteByte('\n')
}
