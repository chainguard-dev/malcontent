// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// markdownTextSpecial lists the bytes that start Markdown, GFM, or GitHub syntax
// in a table cell or in link text: the backslash, code and emphasis markers,
// link brackets and parentheses, HTML angle brackets, the cell separator, and
// the math delimiter.
const markdownTextSpecial = "\\`*_~[]()<>|$"

// markdownTextEntities follows each byte GitHub turns into @mentions, #issue
// references, and :emoji: shortcodes with a zero-width space character
// reference, which keeps GitHub from linking them while the text reads the
// same. '&' becomes "&amp;", so an entity spelled out in untrusted text stays
// literal instead of decoding.
var markdownTextEntities = map[byte]string{
	'&': "&amp;",
	'@': "@&#8203;",
	'#': "#&#8203;",
	':': ":&#8203;",
}

// markdownTableHeader opens every behavior table with a header row and a
// left-aligned separator row.
const markdownTableHeader = "| RISK | KEY | DESCRIPTION | EVIDENCE |\n|:--|:--|:--|:--|\n"

// Markdown renders each file's behaviors as a GFM table. It is safe for
// concurrent use: each File call writes its output with a single Write.
type Markdown struct {
	out blockWriter
}

func NewMarkdown(w io.Writer) *Markdown {
	return &Markdown{out: blockWriter{w: w}}
}

func mdRisk(score int, level string) string {
	return riskEmoji(score) + " " + level
}

// escapeMarkdownCell makes untrusted s literal inside a GFM table cell. Control
// characters, including line endings that would end the table row, become %XX,
// bytes in entities become their replacement, and every byte listed in special
// gets a backslash prefix. Text and link text pass markdownTextSpecial and
// markdownTextEntities. Code spans, where neither backslash escapes nor
// entities apply, pass only "|" and no entities, because GFM tables split cells
// on an unescaped pipe even inside a code span and remove the backslash again.
func escapeMarkdownCell(s, special string, entities map[byte]string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if entity, ok := entities[c]; ok {
			b.WriteString(entity)
			continue
		}
		if c < 0x20 || c == 0x7f {
			writePercent(&b, c)
			continue
		}
		if strings.IndexByte(special, c) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// writePercent writes c percent-encoded, as %XX. Writing through fmt would
// move b to the heap.
func writePercent(b *strings.Builder, c byte) {
	const digits = "0123456789ABCDEF"
	b.WriteByte('%')
	b.WriteByte(digits[c>>4])
	b.WriteByte(digits[c&0x0f])
}

// sanitizeMarkdown escapes untrusted s, such as a scanned file path or evidence,
// for use as heading text, plain text, or link text in a table cell, so it
// cannot end a heading, link, or cell, open an HTML tag, add formatting, or
// trigger GitHub mentions, issue references, or emoji.
func sanitizeMarkdown(s string) string {
	return escapeMarkdownCell(s, markdownTextSpecial, markdownTextEntities)
}

// markdownCodeSpan renders untrusted s as an inline code span in a table cell.
// A code span ends at the first backtick run as long as its opening fence, so
// the fence is one backtick longer than the longest run in s. Content that
// starts or ends with a backtick or a space is padded with one space on each
// side, which the parser strips again.
func markdownCodeSpan(s string) string {
	s = escapeMarkdownCell(s, "|", nil)
	longest, run := 0, 0
	for i := range len(s) {
		if s[i] != '`' {
			run = 0
			continue
		}
		run++
		longest = max(longest, run)
	}
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		s = " " + s + " "
	}
	fence := strings.Repeat("`", longest+1)
	return fence + s + fence
}

// generate a markdown link for a matched fragment.
func matchFragmentLink(s string) string {
	// it's probably the name of a matched YARA field, for example, if it's xor'ed data
	if strings.HasPrefix(s, "$") {
		return markdownCodeSpan(s)
	}

	if strings.HasPrefix(s, "https:") || strings.HasPrefix(s, "http://") {
		return markdownURLLink(s)
	}

	return "[" + sanitizeMarkdown(s) + "](https://github.com/search?q=" + url.QueryEscape(s) + "&type=code)"
}

// markdownURLLink links an untrusted URL to itself. The destination uses the
// angle-bracket form, which accepts spaces and parentheses, and percent-encodes
// the bytes that would still end the destination, the link, or the table cell:
// control characters (including line endings), '<', '>', '\', and '|'. '&' gets
// a backslash so an entity spelled out in the URL is not decoded. The visible
// text is escaped with sanitizeMarkdown.
func markdownURLLink(s string) string {
	var dest strings.Builder
	dest.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c == 0x7f || strings.IndexByte(`<>\|`, c) >= 0 {
			writePercent(&dest, c)
			continue
		}
		if c == '&' {
			dest.WriteByte('\\')
		}
		dest.WriteByte(c)
	}
	return "[" + sanitizeMarkdown(s) + "](<" + dest.String() + ">)"
}

func (r *Markdown) Name() string { return "Markdown" }

func (r *Markdown) Scanning(_ context.Context, _ string) {}

func (r *Markdown) File(ctx context.Context, fr *malcontent.FileReport) error {
	if fr.Skipped != "" || len(fr.Behaviors) == 0 {
		return nil
	}

	b := getBuffer()
	defer putBuffer(b)
	if err := markdownTable(ctx, fr, b, tableConfig{Title: "## " + sanitizeMarkdown(fr.Path) + " [" + mdRisk(fr.RiskScore, fr.RiskLevel) + "]"}); err != nil {
		return err
	}
	return r.out.write(b.Bytes())
}

func (r *Markdown) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if rep == nil || rep.Diff == nil {
		return nil
	}

	b := getBuffer()
	defer putBuffer(b)
	// writeDiff writes each section once it is complete, so b holds output
	// only when a table fails partway through a section. Write that start,
	// so the output matches writing each piece as it is rendered, and return
	// the table's error.
	if err := r.writeDiff(ctx, rep.Diff, b); err != nil {
		_ = r.out.flush(b)
		return err
	}
	return nil
}

// writeDiff renders the sections of d into b and writes each file's section
// once it is complete.
func (r *Markdown) writeDiff(ctx context.Context, d *malcontent.DiffReport, b *bytes.Buffer) error {
	for removed := d.Removed.Oldest(); removed != nil; removed = removed.Next() {
		if len(removed.Value.Behaviors) == 0 {
			continue
		}

		if err := markdownTable(ctx, removed.Value, b, tableConfig{Title: "## Deleted: " + sanitizeMarkdown(removed.Key) + " [" + mdRisk(removed.Value.RiskScore, removed.Value.RiskLevel) + "]", DiffRemoved: true}); err != nil {
			return err
		}
		if err := r.out.flush(b); err != nil {
			return err
		}
	}

	for added := d.Added.Oldest(); added != nil; added = added.Next() {
		if len(added.Value.Behaviors) == 0 {
			continue
		}

		if err := markdownTable(ctx, added.Value, b, tableConfig{Title: "## Added: " + sanitizeMarkdown(added.Key) + " [" + mdRisk(added.Value.RiskScore, added.Value.RiskLevel) + "]", DiffAdded: true}); err != nil {
			return err
		}
		if err := r.out.flush(b); err != nil {
			return err
		}
	}

	for modified := d.Modified.Oldest(); modified != nil; modified = modified.Next() {
		added := 0
		removed := 0
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
			title = fmt.Sprintf("## Moved (%d added, %d removed): %s -> %s", added, removed, sanitizeMarkdown(modified.Value.PreviousPath), sanitizeMarkdown(modified.Value.Path))
		} else {
			title = fmt.Sprintf("## Changed (%d added, %d removed): %s", added, removed, sanitizeMarkdown(modified.Value.Path))
		}

		if modified.Value.RiskScore != modified.Value.PreviousRiskScore {
			title = fmt.Sprintf("%s [%s → %s]",
				title,
				mdRisk(modified.Value.PreviousRiskScore, modified.Value.PreviousRiskLevel),
				mdRisk(modified.Value.RiskScore, modified.Value.RiskLevel))
		}

		b.WriteString(title)
		b.WriteString("\n\n")

		// We split the added/removed up in Markdown to address readability feedback. Unfortunately,
		// this means we hide "existing" behaviors, which causes context to suffer. We should evaluate an
		// improved rendering, similar to the "terminal" refresh, that includes everything.
		var count int
		var qual string
		if added > 0 {
			count = added
			noun := "behavior"
			qual = "new"
			if count > 1 {
				noun = "behaviors"
			}
			if err := markdownTable(ctx, modified.Value, b, tableConfig{
				Title:        fmt.Sprintf("### %d %s %s", count, qual, noun),
				SkipRemoved:  true,
				SkipExisting: true,
				SkipNoDiff:   true,
			}); err != nil {
				return err
			}
		}

		if removed > 0 {
			count = removed
			noun := "behavior"
			qual = "removed"
			if count > 1 {
				noun = "behaviors"
			}
			if err := markdownTable(ctx, modified.Value, b, tableConfig{
				Title:        fmt.Sprintf("### %d %s %s", count, qual, noun),
				SkipAdded:    true,
				SkipExisting: true,
				SkipNoDiff:   true,
			}); err != nil {
				return err
			}
		}

		if err := r.out.flush(b); err != nil {
			return err
		}
	}
	return nil
}

// markdownTable writes fr's behaviors to b as a GFM table under rc.Title,
// highest risk first, keeping the rows that rc selects.
func markdownTable(ctx context.Context, fr *malcontent.FileReport, b *bytes.Buffer, rc tableConfig) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr.Skipped != "" {
		return nil
	}

	if len(fr.Behaviors) == 0 {
		if fr.PreviousRelPath != "" && rc.Title != "" {
			b.WriteString(rc.Title)
			b.WriteString("\n\n")
		}
		return nil
	}

	if rc.Title != "" {
		b.WriteString(rc.Title)
		b.WriteString("\n\n")
	}

	kbs := make([]KeyedBehavior, 0, len(fr.Behaviors))
	for _, bh := range fr.Behaviors {
		kbs = append(kbs, KeyedBehavior{Key: bh.ID, Behavior: bh})
	}

	// Highest risk first, then by key.
	slices.SortFunc(kbs, func(x, y KeyedBehavior) int {
		return cmp.Or(
			cmp.Compare(y.Behavior.RiskScore, x.Behavior.RiskScore),
			cmp.Compare(x.Key, y.Key),
		)
	})

	// Each cell gets exactly one space of padding on each side and is
	// otherwise written as given, so link destinations and other cell content
	// are never altered.
	b.WriteString(markdownTableHeader)
	for _, k := range kbs {
		bh := k.Behavior
		risk := bh.RiskLevel

		if rc.SkipExisting && !bh.DiffAdded && !bh.DiffRemoved {
			continue
		}

		if (!bh.DiffRemoved && !bh.DiffAdded) || rc.NoDiff {
			if rc.SkipNoDiff {
				continue
			}
		}

		if bh.DiffAdded || rc.DiffAdded {
			if rc.SkipAdded {
				continue
			}
			risk = "+" + risk
		}
		if bh.DiffRemoved || rc.DiffRemoved {
			if rc.SkipRemoved {
				continue
			}
			risk = "-" + risk
		}

		key := "[" + k.Key + "](" + bh.RuleURL + ")"
		if strings.HasPrefix(risk, "+") {
			key = "**" + key + "**"
		}

		b.WriteByte('|')
		writeMarkdownCell(b, risk)
		writeMarkdownCell(b, key)
		writeMarkdownCell(b, markdownDescription(bh))
		writeMarkdownCell(b, markdownEvidence(bh.MatchStrings))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return nil
}

// markdownDescription returns the first sentence of bh's description, linked
// to its reference and followed by its author.
func markdownDescription(bh *malcontent.Behavior) string {
	desc, _, _ := strings.Cut(bh.Description, ". ")

	if bh.ReferenceURL != "" {
		desc = "[" + desc + "](" + bh.ReferenceURL + ")"
	}

	if bh.RuleAuthor != "" {
		author := bh.RuleAuthor
		if bh.RuleAuthorURL != "" {
			author = "[" + author + "](" + bh.RuleAuthorURL + ")"
		}

		if desc != "" {
			desc += ", by " + author
		} else {
			desc = "by " + author
		}
	}
	return desc
}

// markdownEvidence returns the links for matched strings, separated by line
// breaks. A single link is returned as is, without copying it.
func markdownEvidence(ms []string) string {
	if len(ms) == 1 {
		return matchFragmentLink(ms[0])
	}
	var b strings.Builder
	for i, m := range ms {
		if i > 0 {
			b.WriteString("<br>")
		}
		b.WriteString(matchFragmentLink(m))
	}
	return b.String()
}

// writeMarkdownCell writes cell, without surrounding white space, and the
// separator that ends it. An empty cell is a single space.
func writeMarkdownCell(b *bytes.Buffer, cell string) {
	if cell = strings.TrimSpace(cell); cell != "" {
		b.WriteByte(' ')
		b.WriteString(cell)
	}
	b.WriteString(" |")
}
