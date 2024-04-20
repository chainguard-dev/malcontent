// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/olekukonko/tablewriter"
)

type Markdown struct {
	w io.Writer
}

func NewMarkdown(w io.Writer) Markdown {
	return Markdown{w: w}
}

func (r Markdown) File(ctx context.Context, fr bincapz.FileReport) error {
	markdownTable(ctx, &fr, r.w, tableConfig{Title: fmt.Sprintf("## %s\n\nOverall risk: %s", fr.Path, decorativeRisk(fr.RiskScore, fr.RiskLevel))})
	return nil
}

func (r Markdown) Full(ctx context.Context, rep bincapz.Report) error {
	for f, fr := range rep.Diff.Removed {
		fr := fr
		markdownTable(ctx, &fr, r.w, tableConfig{Title: fmt.Sprintf("## Deleted: %s", f), DiffRemoved: true})
	}

	for f, fr := range rep.Diff.Added {
		fr := fr
		markdownTable(ctx, &fr, r.w, tableConfig{Title: fmt.Sprintf("## Added: %s\n\nOverall risk: %s", f, decorativeRisk(fr.RiskScore, fr.RiskLevel)), DiffAdded: true})
	}

	for f, fr := range rep.Diff.Modified {
		fr := fr
		var title string
		if fr.PreviousRelPath != "" {
			title = fmt.Sprintf("## Moved: %s -> %s (score: %f)", fr.PreviousRelPath, f, fr.PreviousRelPathScore)
		} else {
			title = fmt.Sprintf("## Changed: %s\n", f)
		}
		if fr.RiskScore != fr.PreviousRiskScore {
			title = fmt.Sprintf("%s\nPrevious Risk: %s\nNew Risk:      %s",
				title,
				decorativeRisk(fr.PreviousRiskScore, fr.PreviousRiskLevel),
				decorativeRisk(fr.RiskScore, fr.RiskLevel))
		}
		markdownTable(ctx, &fr, r.w, tableConfig{Title: title})
	}
	return nil
}

// generate a markdown link for matched text
func matchLink(s string) string {
	// it's probably the name of a matched YARA field, for example, if it's xor'ed data
	if strings.HasPrefix(s, "$") {
		return s
	}

	if strings.HasPrefix(s, "https:") || strings.HasPrefix(s, "http://") {
		return fmt.Sprintf("[%s](%s)", s, s)
	}

	return fmt.Sprintf("[%s](https://github.com/search?q=%s&type=code)", s, url.QueryEscape(s))
}

func markdownTable(_ context.Context, fr *bincapz.FileReport, w io.Writer, rc tableConfig) {
	path := fr.Path
	if fr.Error != "" {
		fmt.Printf("⚠️ %s - error: %s\n", path, fr.Error)
		return
	}

	if fr.Skipped != "" {
		return
	}

	kbs := []KeyedBehavior{}
	for k, b := range fr.Behaviors {
		kbs = append(kbs, KeyedBehavior{Key: k, Behavior: b})
	}

	if len(kbs) == 0 {
		if fr.PreviousRelPath != "" && rc.Title != "" {
			fmt.Fprintf(w, "%s\n\n", rc.Title)
		}
		return
	}

	if rc.Title != "" {
		fmt.Fprintf(w, "%s\n\n", rc.Title)
	}

	sort.Slice(kbs, func(i, j int) bool {
		if kbs[i].Behavior.RiskScore == kbs[j].Behavior.RiskScore {
			return kbs[i].Key < kbs[j].Key
		}
		return kbs[i].Behavior.RiskScore > kbs[j].Behavior.RiskScore
	})

	data := [][]string{}

	if len(data) > 0 {
		data = append(data, []string{"", "", ""})
	}

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

		// lowercase first character for consistency
		risk := k.Behavior.RiskLevel
		if k.Behavior.DiffAdded || rc.DiffAdded {
			risk = fmt.Sprintf("+%s", risk)
		}
		if k.Behavior.DiffRemoved || rc.DiffRemoved {
			risk = fmt.Sprintf("-%s", risk)
		}

		key := fmt.Sprintf("[%s](%s)", k.Key, k.Behavior.RuleURL)
		if strings.HasPrefix(risk, "+") {
			key = fmt.Sprintf("**%s**", key)
		}

		matchLinks := []string{}
		for _, m := range k.Behavior.MatchStrings {
			matchLinks = append(matchLinks, matchLink(m))
		}
		evidence := strings.Join(matchLinks, "<br>")
		data = append(data, []string{risk, key, desc, evidence})
	}
	table := tablewriter.NewWriter(w)
	table.SetAutoWrapText(false)
	table.SetHeader([]string{"Risk", "Key", "Description", "Evidence"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(data) // Add Bulk Data
	table.Render()
	fmt.Fprintln(w, "")
}
