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

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/olekukonko/tablewriter"
)

type Markdown struct {
	w io.Writer
}

func NewMarkdown(w io.Writer) Markdown {
	return Markdown{w: w}
}

func mdRisk(score int, level string) string {
	return fmt.Sprintf("%s %s", riskEmoji(score), level)
}

// generate a markdown link for a matched fragment.
func matchFragmentLink(s string) string {
	// it's probably the name of a matched YARA field, for example, if it's xor'ed data
	if strings.HasPrefix(s, "$") {
		return s
	}

	if strings.HasPrefix(s, "https:") || strings.HasPrefix(s, "http://") {
		return fmt.Sprintf("[%s](%s)", s, s)
	}

	return fmt.Sprintf("[%s](https://github.com/search?q=%s&type=code)", s, url.QueryEscape(s))
}

func (r Markdown) Name() string { return "Markdown" }

func (r Markdown) Scanning(_ context.Context, _ string) {}

func (r Markdown) File(ctx context.Context, fr *malcontent.FileReport) error {
	if fr.Skipped == "" && len(fr.Behaviors) > 0 {
		markdownTable(ctx, fr, r.w, tableConfig{Title: fmt.Sprintf("## %s [%s]", fr.Path, mdRisk(fr.RiskScore, fr.RiskLevel))})
	}
	return nil
}

func (r Markdown) Full(ctx context.Context, rep *malcontent.Report) error {
	if rep.Diff == nil {
		return nil
	}

	for removed := rep.Diff.Removed.Oldest(); removed != nil; removed = removed.Next() {
		markdownTable(ctx, removed.Value, r.w, tableConfig{Title: fmt.Sprintf("## Deleted: %s [%s]", removed.Key, mdRisk(removed.Value.RiskScore, removed.Value.RiskLevel)), DiffRemoved: true})
	}

	for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
		markdownTable(ctx, added.Value, r.w, tableConfig{Title: fmt.Sprintf("## Added: %s [%s]", added.Key, mdRisk(added.Value.RiskScore, added.Value.RiskLevel)), DiffAdded: true})
	}

	for modified := rep.Diff.Modified.Oldest(); modified != nil; modified = modified.Next() {
		var title string
		if modified.Value.PreviousRelPath != "" && modified.Value.PreviousRelPathScore >= 0.9 {
			title = fmt.Sprintf("## Moved: %s -> %s (similarity: %0.2f)", modified.Value.PreviousPath, modified.Value.Path, modified.Value.PreviousRelPathScore)
		} else {
			title = fmt.Sprintf("## Changed: %s", modified.Value.Path)
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
			markdownTable(ctx, modified.Value, r.w, tableConfig{
				Title:        fmt.Sprintf("### %d %s %s", count, qual, noun),
				SkipRemoved:  true,
				SkipExisting: true,
				SkipNoDiff:   true,
			})
		}

		if removed > 0 {
			count = removed
			noun := "behavior"
			qual = "removed"
			if count > 1 {
				noun = "behaviors"
			}
			markdownTable(ctx, modified.Value, r.w, tableConfig{
				Title:        fmt.Sprintf("### %d %s %s", count, qual, noun),
				SkipAdded:    true,
				SkipExisting: true,
				SkipNoDiff:   true,
			})
		}

		if noDiff > 0 {
			count = noDiff
			noun := "behavior"
			qual = "consistent"
			if count > 1 {
				noun = "behaviors"
			}
			markdownTable(ctx, modified.Value, r.w, tableConfig{
				Title:       fmt.Sprintf("### %d %s %s", count, qual, noun),
				SkipAdded:   true,
				SkipRemoved: true,
			})
		}
	}
	return nil
}

func markdownTable(_ context.Context, fr *malcontent.FileReport, w io.Writer, rc tableConfig) {
	path := fr.Path
	if fr.Error != "" {
		fmt.Printf("⚠️ %s - error: %s\n", path, fr.Error)
		return
	}

	if fr.Skipped != "" {
		return
	}

	kbs := make([]KeyedBehavior, 0, len(fr.Behaviors))
	for _, b := range fr.Behaviors {
		kbs = append(kbs, KeyedBehavior{Key: b.ID, Behavior: b})
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

	data := make([][]string, 0, len(kbs))
	for _, k := range kbs {
		data = append(data, make([]string, 0, len(k.Behavior.MatchStrings)))
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

		risk := k.Behavior.RiskLevel

		if rc.SkipExisting && !(k.Behavior.DiffAdded || k.Behavior.DiffRemoved) {
			continue
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
		if (!k.Behavior.DiffRemoved && !k.Behavior.DiffAdded) || rc.NoDiff {
			if rc.SkipNoDiff {
				continue
			}
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
