// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/term"
)

var maxExampleCount = 8

type KeyedBehavior struct {
	Key      string
	Behavior *malcontent.Behavior
}

type tableConfig struct {
	Title       string
	ShowTitle   bool
	DiffRemoved bool
	DiffAdded   bool
	SkipAdded   bool
	SkipRemoved bool
}

func terminalWidth(ctx context.Context) int {
	if !term.IsTerminal(0) {
		return 120
	}

	width, _, err := term.GetSize(0)
	if err != nil {
		clog.ErrorContext(ctx, "term.getsize", slog.Any("error", err))
		return 80
	}

	return width
}

type Terminal struct {
	w io.Writer
}

func NewTerminal(w io.Writer) Terminal {
	return Terminal{w: w}
}

func decorativeRisk(score int, level string) string {
	return fmt.Sprintf("%s %s", riskEmoji(score), riskColor(level, level))
}

func darkBrackets(s string) string {
	return fmt.Sprintf("%s%s%s", color.HiBlackString("["), s, color.HiBlackString("]"))
}

func riskInColor(level string) string {
	return riskColor(level, level)
}

func riskColor(level string, text string) string {
	switch level {
	case "LOW":
		return color.HiGreenString(text)
	case "MEDIUM", "MED":
		return color.HiYellowString(text)
	case "HIGH":
		return color.HiRedString(text)
	case "CRITICAL", "CRIT":
		return color.HiMagentaString(text)
	default:
		return color.WhiteString(text)
	}
}

func ShortRisk(s string) string {
	if len(s) < 4 {
		return s
	}
	short := s[0:4]
	if s == "MEDIUM" {
		return "MED"
	}
	return short
}

func (r Terminal) Scanning(_ context.Context, path string) {
	fmt.Fprintf(r.w, "🔎 Scanning %q\n", path)
}

func (r Terminal) File(ctx context.Context, fr *malcontent.FileReport) error {
	if len(fr.Behaviors) > 0 {
		renderTable(ctx, fr, r.w,
			tableConfig{
				Title: fmt.Sprintf("%s %s", fr.Path, darkBrackets(decorativeRisk(fr.RiskScore, fr.RiskLevel))),
			},
		)
	}
	return nil
}

func (r Terminal) Full(ctx context.Context, rep *malcontent.Report) error {
	// Non-diff files are handled on the fly by File()
	if rep.Diff == nil {
		return nil
	}

	for removed := rep.Diff.Removed.Oldest(); removed != nil; removed = removed.Next() {
		renderTable(ctx, removed.Value, r.w, tableConfig{
			Title:       fmt.Sprintf("Deleted: %s %s", removed.Key, darkBrackets(decorativeRisk(removed.Value.RiskScore, removed.Value.RiskLevel))),
			DiffRemoved: true,
		})
	}

	for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
		renderTable(ctx, added.Value, r.w, tableConfig{
			Title:     fmt.Sprintf("Added: %s %s", added.Key, darkBrackets(decorativeRisk(added.Value.RiskScore, added.Value.RiskLevel))),
			DiffAdded: true,
		})
	}

	for modified := rep.Diff.Modified.Oldest(); modified != nil; modified = modified.Next() {
		var title string
		if modified.Value.PreviousRelPath != "" && modified.Value.PreviousRelPathScore >= 0.9 {
			title = fmt.Sprintf("Moved: %s -> %s (score: %f)", modified.Value.PreviousRelPath, modified.Value.Path, modified.Value.PreviousRelPathScore)
		} else {
			title = fmt.Sprintf("Changed: %s", modified.Value.Path)
		}

		if modified.Value.RiskScore != modified.Value.PreviousRiskScore {
			title = fmt.Sprintf("%s %s\n\n", title,
				darkBrackets(fmt.Sprintf("%s %s %s", decorativeRisk(modified.Value.PreviousRiskScore, modified.Value.PreviousRiskLevel), color.HiWhiteString("→"), decorativeRisk(modified.Value.RiskScore, modified.Value.RiskLevel))))
		}

		if len(modified.Value.Behaviors) > 0 {
			fmt.Fprint(r.w, title)
		}
		added := 0
		removed := 0
		for _, b := range modified.Value.Behaviors {
			if b.DiffAdded {
				added++
			}
			if b.DiffRemoved {
				removed++
			}
		}

		if added > 0 {
			renderTable(ctx, modified.Value, r.w, tableConfig{
				Title:       color.HiWhiteString("+++ ADDED: %d behavior(s) +++", added),
				SkipRemoved: true,
			})
		}

		if removed > 0 {
			renderTable(ctx, modified.Value, r.w, tableConfig{
				Title:     color.HiWhiteString("--- REMOVED: %d behavior(s) ---", removed),
				SkipAdded: true,
			})
		}
	}

	return nil
}

func wrap(s string, i int) string {
	w, _ := tablewriter.WrapString(s, i)
	return strings.Join(w, "\n")
}

func wrapKey(s string, i int) string {
	w := wrap(strings.ReplaceAll(s, "/", " "), i)
	w = strings.ReplaceAll(w, " ", "/")
	return strings.ReplaceAll(w, "\n", "/\n")
}

func darkenText(s string) string {
	split := strings.Split(s, "\n")
	cw := make([]string, 0, len(split))
	for _, w := range split {
		cw = append(cw, color.HiBlackString(w))
	}
	return strings.Join(cw, "\n")
}

func renderTable(ctx context.Context, fr *malcontent.FileReport, w io.Writer, rc tableConfig) {
	title := rc.Title

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
		if fr.PreviousRelPath != "" && title != "" {
			fmt.Fprintf(w, "%s\n", title)
		}
		return
	}

	sort.Slice(kbs, func(i, j int) bool {
		if kbs[i].Behavior.RiskScore == kbs[j].Behavior.RiskScore {
			return kbs[i].Key < kbs[j].Key
		}
		return kbs[i].Behavior.RiskScore < kbs[j].Behavior.RiskScore
	})

	data := make([][]string, 0, len(kbs))
	for _, k := range kbs {
		data = append(data, make([]string, 0, len(k.Behavior.MatchStrings)))
	}

	tWidth := terminalWidth(ctx)
	keyWidth := 24
	descWidth := 30
	extraWidth := 12

	if tWidth >= 100 {
		keyWidth = 30
		descWidth = 45
	}

	if tWidth >= 120 {
		keyWidth = 32
		descWidth = 54
	}

	maxEvidenceWidth := tWidth - keyWidth - extraWidth - descWidth
	longestEvidence := 0

	for _, k := range kbs {
		for _, e := range k.Behavior.MatchStrings {
			if len(e) > maxEvidenceWidth {
				longestEvidence = maxEvidenceWidth
				break
			}

			if len(e) > longestEvidence {
				longestEvidence = len(e)
			}
		}
	}

	for _, k := range kbs {
		desc := k.Behavior.Description
		before, _, found := strings.Cut(desc, ". ")
		if found {
			desc = before
		}
		if k.Behavior.RuleAuthor != "" {
			if desc != "" {
				desc = fmt.Sprintf("%s, by %s", desc, k.Behavior.RuleAuthor)
			} else {
				desc = fmt.Sprintf("by %s", k.Behavior.RuleAuthor)
			}
		}

		abbreviatedEv := []string{}
		for _, e := range k.Behavior.MatchStrings {
			if len(e) > maxEvidenceWidth {
				e = e[0:maxEvidenceWidth-1] + "…"
			}
			abbreviatedEv = append(abbreviatedEv, e)
			if len(abbreviatedEv) >= maxExampleCount {
				abbreviatedEv = append(abbreviatedEv, "…")
				break
			}
		}
		evidence := strings.Join(abbreviatedEv, "\n")

		risk := riskInColor(ShortRisk(k.Behavior.RiskLevel))
		if k.Behavior.DiffAdded || rc.DiffAdded {
			if rc.SkipAdded {
				continue
			}
			risk = fmt.Sprintf("%s%s", color.HiWhiteString("+"), riskInColor(ShortRisk(k.Behavior.RiskLevel)))
		}

		wKey := wrapKey(k.Key, keyWidth)
		wDesc := wrap(desc, descWidth)

		if k.Behavior.DiffRemoved || rc.DiffRemoved {
			if rc.SkipRemoved {
				continue
			}
			risk = fmt.Sprintf("%s%s", color.WhiteString("-"), riskInColor(ShortRisk(k.Behavior.RiskLevel)))
			evidence = darkenText(evidence)
		}

		data = append(data, []string{risk, wKey, wDesc, evidence})
	}

	if title != "" {
		fmt.Fprintf(w, "%s", title)
	}
	fmt.Fprintf(w, "\n")

	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{"risk", "key", "description", "evidence"})

	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("-")
	table.SetHeaderLine(true)
	table.SetBorder(true)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)
	table.AppendBulk(data)
	table.Render()
	fmt.Fprintf(w, "\n")
}
