// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

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

func riskInColor(level string) string {
	return riskColor(level, level)
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
	p.risk(fr.RiskLevel).wrap(b, fr.RiskLevel)
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

	for removed := rep.Diff.Removed.Oldest(); removed != nil; removed = removed.Next() {
		if len(removed.Value.Behaviors) == 0 {
			continue
		}

		title := fmt.Sprintf(riskColor(removed.Value.RiskLevel, "Deleted: %s %s"), sanitizeTerminal(removed.Key), darkBrackets(riskInColor(removed.Value.RiskLevel)))
		renderFileSummary(ctx, b, removed.Value, title, r.width)
		if err := r.out.flush(b); err != nil {
			return err
		}
	}

	for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
		if len(added.Value.Behaviors) == 0 {
			continue
		}

		title := fmt.Sprintf(riskColor(added.Value.RiskLevel, "Added: %s %s"), sanitizeTerminal(added.Key), darkBrackets(riskInColor(added.Value.RiskLevel)))
		renderFileSummary(ctx, b, added.Value, title, r.width)
		if err := r.out.flush(b); err != nil {
			return err
		}
	}

	for modified := rep.Diff.Modified.Oldest(); modified != nil; modified = modified.Next() {
		// Count added and removed behaviors
		var added, removed int
		for _, bh := range modified.Value.Behaviors {
			if bh.DiffAdded {
				added++
			}
			if bh.DiffRemoved {
				removed++
			}
		}

		if added == 0 && removed == 0 {
			continue
		}

		var title string
		if modified.Value.PreviousPath != "" {
			title = fmt.Sprintf(riskColor(modified.Value.PreviousRiskLevel, "Moved (%d added, %d removed): %s -> %s"), added, removed, sanitizeTerminal(modified.Value.PreviousPath), sanitizeTerminal(modified.Value.Path))
		} else {
			title = fmt.Sprintf(riskColor(modified.Value.RiskLevel, "Changed (%d added, %d removed): %s"), added, removed, sanitizeTerminal(modified.Value.Path))
		}
		if modified.Value.RiskScore != modified.Value.PreviousRiskScore {
			title = fmt.Sprintf("%s %s", title,
				darkBrackets(fmt.Sprintf("%s %s %s", riskInColor(modified.Value.PreviousRiskLevel), currentPalette().hiWhite.sprint("→"), riskInColor(modified.Value.RiskLevel))))
		}

		renderFileSummary(ctx, b, modified.Value, title, r.width)
		if err := r.out.flush(b); err != nil {
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
// longer than width bytes: it keeps the first width-1 bytes and appends an
// ellipsis.
func truncateLine(b *bytes.Buffer, start, width int) {
	if b.Len()-start > width {
		b.Truncate(start + width - 1)
		b.WriteString("…")
	}
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

// renderFileSummary renders fr under title, which the caller builds, including any diff counts and risk transition.
func renderFileSummary(ctx context.Context, b *bytes.Buffer, fr *malcontent.FileReport, title string, width int) {
	if ctx.Err() != nil || fr.Skipped != "" {
		return
	}

	writeSummaryHeader(b, fr.RiskScore)
	b.WriteString(title)
	b.WriteByte('\n')
	writeSummaryBody(b, currentPalette(), fr, width)
}

// writeSummaryHeader starts the first line of a file summary, up to its title.
func writeSummaryHeader(b *bytes.Buffer, riskScore int) {
	b.WriteString("├─ ")
	b.WriteString(riskEmoji(riskScore))
	b.WriteByte(' ')
}

// nsGroup holds what a file summary prints for one namespace.
type nsGroup struct {
	ns   string
	long string // nsLongName(ns)
	// index is the namespace's position in order of first appearance.
	index int
	// risk is the highest risk score of its behaviors that were not just removed, or 0.
	risk int
	// prevRisk is the highest risk score of its behaviors that were not just added, or 0.
	prevRisk int
}

// writeSummaryBody writes fr's behaviors grouped by namespace, then the
// closing bar. Namespaces print in order of the length of their long names;
// those whose long names are the same length print in the order they first
// appear.
func writeSummaryBody(b *bytes.Buffer, p *palette, fr *malcontent.FileReport, width int) {
	groups := make([]nsGroup, 0, 16)
	groupOf := make([]int, 0, 64)
	diffMode := false
	// anyPrevious records whether any namespace has a previous risk above 0;
	// only then can a namespace line show a risk transition.
	anyPrevious := false

	for _, bh := range fr.Behaviors {
		ns, _ := splitRuleID(bh.ID)
		g := slices.IndexFunc(groups, func(x nsGroup) bool { return x.ns == ns })
		if g < 0 {
			g = len(groups)
			groups = append(groups, nsGroup{ns: ns, long: nsLongName(ns), index: g})
		}
		groupOf = append(groupOf, g)

		if bh.DiffAdded || bh.DiffRemoved {
			diffMode = true
		}
		grp := &groups[g]
		if !bh.DiffAdded && bh.RiskScore > grp.prevRisk {
			grp.prevRisk = bh.RiskScore
			anyPrevious = true
		}
		if !bh.DiffRemoved {
			grp.risk = max(grp.risk, bh.RiskScore)
		}
	}

	slices.SortStableFunc(groups, func(x, y nsGroup) int {
		return cmp.Compare(len(x.long), len(y.long))
	})

	for i := range groups {
		g := &groups[i]
		writeNamespaceLine(b, p, g, anyPrevious)
		for j, bh := range fr.Behaviors {
			if groupOf[j] == g.index {
				writeBehaviorLine(b, p, bh, diffMode, width)
			}
		}
	}
	b.WriteString("│\n")
}

// writeNamespaceLine writes the line that introduces a namespace: its long
// name and risk level, and how the risk changed when it did.
func writeNamespaceLine(b *bytes.Buffer, p *palette, g *nsGroup, anyPrevious bool) {
	level := riskLevels[g.risk]
	// The zero sgr writes the diff marker and the icon without escape sequences.
	var diffStyle, iconStyle sgr
	diff, icon := " ", "≡"

	changed := anyPrevious && g.risk != g.prevRisk
	var previousLevel string
	if changed {
		previousLevel = riskLevels[g.prevRisk]
		iconStyle, icon = p.hiYellow, "▲"
		if g.risk < g.prevRisk {
			iconStyle, icon = p.hiGreen, "▼"
		}
		// A namespace whose risk rises from NONE is marked added, and one whose
		// risk falls to NONE, removed.
		switch {
		case previousLevel == report.LevelNONE:
			diffStyle, diff = p.hiGreen, "+"
		case level == report.LevelNONE:
			diffStyle, diff = p.hiRed, "-"
		}
	}

	b.WriteString("│")
	diffStyle.wrap(b, diff)
	b.WriteString("    ")
	iconStyle.wrap(b, icon)
	b.WriteByte(' ')
	b.WriteString(g.long)
	b.WriteByte(' ')
	p.hiBlack.wrap(b, "[")
	if changed {
		p.risk(previousLevel).wrap(b, previousLevel)
		b.WriteString(" → ")
	}
	p.risk(level).wrap(b, level)
	p.hiBlack.wrap(b, "]")
	b.WriteByte('\n')
}

// writeBehaviorLine writes one behavior and its evidence. In diff mode it
// writes only added and removed behaviors and drops the evidence of removed
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
		if !bh.DiffAdded && !bh.DiffRemoved {
			return
		}
	}

	// Outside diff mode no behavior is marked removed.
	var e string
	if !bh.DiffRemoved {
		e = sanitizeTerminal(evidenceString(bh.MatchStrings, bh.Description))
	}

	_, rest := splitRuleID(bh.ID)
	desc, _, _ := strings.Cut(bh.Description, " - ")
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
		b.WriteString(bh.RuleAuthor)
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
