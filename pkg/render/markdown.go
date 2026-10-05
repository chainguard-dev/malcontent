// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
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

type Markdown struct {
	w io.Writer
}

func NewMarkdown(w io.Writer) Markdown {
	return Markdown{w: w}
}

func mdRisk(score int, level string) string {
	return fmt.Sprintf("%s %s", riskEmoji(score), level)
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
		switch {
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&b, "%%%02X", c)
		case strings.IndexByte(special, c) >= 0:
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
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

	safe := sanitizeMarkdown(s)
	return fmt.Sprintf("[%s](https://github.com/search?q=%s&type=code)", safe, url.QueryEscape(s))
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
		switch {
		case c < 0x20 || c == 0x7f || strings.IndexByte(`<>\|`, c) >= 0:
			fmt.Fprintf(&dest, "%%%02X", c)
		case c == '&':
			dest.WriteString(`\&`)
		default:
			dest.WriteByte(c)
		}
	}
	return fmt.Sprintf("[%s](<%s>)", sanitizeMarkdown(s), dest.String())
}

func (r Markdown) Name() string { return "Markdown" }

func (r Markdown) Scanning(_ context.Context, _ string) {}

func (r Markdown) File(ctx context.Context, fr *malcontent.FileReport) error {
	if fr.Skipped == "" && len(fr.Behaviors) > 0 {
		if err := markdownTable(ctx, fr, r.w, tableConfig{Title: fmt.Sprintf("## %s [%s]", sanitizeMarkdown(fr.Path), mdRisk(fr.RiskScore, fr.RiskLevel))}); err != nil {
			return err
		}
	}
	return nil
}

func (r Markdown) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if rep == nil || rep.Diff == nil {
		return nil
	}

	for removed := rep.Diff.Removed.Oldest(); removed != nil; removed = removed.Next() {
		if len(removed.Value.Behaviors) == 0 {
			continue
		}

		if err := markdownTable(ctx, removed.Value, r.w, tableConfig{Title: fmt.Sprintf("## Deleted: %s [%s]", sanitizeMarkdown(removed.Key), mdRisk(removed.Value.RiskScore, removed.Value.RiskLevel)), DiffRemoved: true}); err != nil {
			return err
		}
	}

	for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
		if len(added.Value.Behaviors) == 0 {
			continue
		}

		if err := markdownTable(ctx, added.Value, r.w, tableConfig{Title: fmt.Sprintf("## Added: %s [%s]", sanitizeMarkdown(added.Key), mdRisk(added.Value.RiskScore, added.Value.RiskLevel)), DiffAdded: true}); err != nil {
			return err
		}
	}

	for modified := rep.Diff.Modified.Oldest(); modified != nil; modified = modified.Next() {
		if len(modified.Value.Behaviors) == 0 {
			continue
		}

		added := 0
		removed := 0
		noDiff := 0
		for _, b := range modified.Value.Behaviors {
			if b.DiffAdded {
				added++
			}
			if b.DiffRemoved {
				removed++
			}
			if !b.DiffAdded && !b.DiffRemoved {
				noDiff++
			}
		}

		if added == 0 && removed == 0 {
			continue
		}

		var title string
		switch {
		case modified.Value.PreviousPath != "":
			title = fmt.Sprintf("## Moved (%d added, %d removed): %s -> %s", added, removed, sanitizeMarkdown(modified.Value.PreviousPath), sanitizeMarkdown(modified.Value.Path))
		default:
			title = fmt.Sprintf("## Changed (%d added, %d removed): %s", added, removed, sanitizeMarkdown(modified.Value.Path))
		}

		if modified.Value.RiskScore != modified.Value.PreviousRiskScore {
			title = fmt.Sprintf("%s [%s → %s]",
				title,
				mdRisk(modified.Value.PreviousRiskScore, modified.Value.PreviousRiskLevel),
				mdRisk(modified.Value.RiskScore, modified.Value.RiskLevel))
		}

		if len(modified.Value.Behaviors) > 0 {
			fmt.Fprint(r.w, title+"\n\n")
		}

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
			if err := markdownTable(ctx, modified.Value, r.w, tableConfig{
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
			if err := markdownTable(ctx, modified.Value, r.w, tableConfig{
				Title:        fmt.Sprintf("### %d %s %s", count, qual, noun),
				SkipAdded:    true,
				SkipExisting: true,
				SkipNoDiff:   true,
			}); err != nil {
				return err
			}
		}

		if noDiff > 0 {
			continue
		}
	}
	return nil
}

func markdownTable(ctx context.Context, fr *malcontent.FileReport, w io.Writer, rc tableConfig) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr.Skipped != "" {
		return nil
	}

	kbs := make([]KeyedBehavior, 0, len(fr.Behaviors))
	for _, b := range fr.Behaviors {
		kbs = append(kbs, KeyedBehavior{Key: b.ID, Behavior: b})
	}

	if len(kbs) == 0 {
		if fr.PreviousRelPath != "" && rc.Title != "" {
			fmt.Fprintf(w, "%s\n\n", rc.Title)
		}
		return nil
	}

	if rc.Title != "" {
		fmt.Fprintf(w, "%s\n\n", rc.Title)
	}

	// Highest risk first, then by key.
	slices.SortFunc(kbs, func(a, b KeyedBehavior) int {
		return cmp.Or(
			cmp.Compare(b.Behavior.RiskScore, a.Behavior.RiskScore),
			cmp.Compare(a.Key, b.Key),
		)
	})

	rows := make([][]string, 0, len(kbs))
	for _, k := range kbs {
		desc := k.Behavior.Description
		before, _, found := strings.Cut(desc, ". ")
		if found {
			desc = before
		}

		if k.Behavior.ReferenceURL != "" {
			desc = fmt.Sprintf("[%s](%s)", desc, k.Behavior.ReferenceURL)
		}

		if k.Behavior.RuleAuthor != "" {
			author := k.Behavior.RuleAuthor
			if k.Behavior.RuleAuthorURL != "" {
				author = fmt.Sprintf("[%s](%s)", author, k.Behavior.RuleAuthorURL)
			}

			if desc != "" {
				desc = fmt.Sprintf("%s, by %s", desc, author)
			} else {
				desc = fmt.Sprintf("by %s", author)
			}
		}

		risk := k.Behavior.RiskLevel

		if rc.SkipExisting && !k.Behavior.DiffAdded && !k.Behavior.DiffRemoved {
			continue
		}

		if (!k.Behavior.DiffRemoved && !k.Behavior.DiffAdded) || rc.NoDiff {
			if rc.SkipNoDiff {
				continue
			}
		}

		if k.Behavior.DiffAdded || rc.DiffAdded {
			if rc.SkipAdded {
				continue
			}
			risk = fmt.Sprintf("+%s", risk)
		}
		if k.Behavior.DiffRemoved || rc.DiffRemoved {
			if rc.SkipRemoved {
				continue
			}
			risk = fmt.Sprintf("-%s", risk)
		}

		key := fmt.Sprintf("[%s](%s)", k.Key, k.Behavior.RuleURL)
		if strings.HasPrefix(risk, "+") {
			key = fmt.Sprintf("**%s**", key)
		}

		matchLinks := make([]string, 0, len(k.Behavior.MatchStrings))
		for _, m := range k.Behavior.MatchStrings {
			matchLinks = append(matchLinks, matchFragmentLink(m))
		}
		evidence := strings.Join(matchLinks, "<br>")
		rows = append(rows, []string{risk, key, desc, evidence})
	}

	writeMarkdownTable(w, rows)
	return nil
}

// writeMarkdownTable writes rows as a GFM table followed by a blank line. Each
// cell gets exactly one space of padding on each side and is otherwise written
// as given, so link destinations and other cell content are never altered.
func writeMarkdownTable(w io.Writer, rows [][]string) {
	var b strings.Builder
	b.WriteString(markdownTableHeader)
	for _, row := range rows {
		b.WriteByte('|')
		for _, cell := range row {
			if cell = strings.TrimSpace(cell); cell != "" {
				b.WriteString(" " + cell)
			}
			b.WriteString(" |")
		}
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	fmt.Fprint(w, b.String())
}
