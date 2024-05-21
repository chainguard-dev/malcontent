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

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/clog"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/term"
)

var maxExampleCount = 8

type KeyedBehavior struct {
	Key      string
	Behavior *bincapz.Behavior
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
	return fmt.Sprintf("%s %s", riskEmoji(score), riskColor(level))
}

func darkBrackets(s string) string {
	return fmt.Sprintf("%s%s%s", color.HiBlackString("["), s, color.HiBlackString("]"))
}

func riskColor(level string) string {
	switch level {
	case "LOW":
		return color.HiGreenString(level)
	case "MEDIUM", "MED":
		return color.HiYellowString(level)
	case "HIGH":
		return color.HiRedString(level)
	case "CRITICAL", "CRIT":
		return color.HiMagentaString(level)
	default:
		return color.WhiteString(level)
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

func (r Terminal) File(ctx context.Context, fr *bincapz.FileReport) error {
	renderTable(ctx, fr, r.w,
		tableConfig{
			Title: fmt.Sprintf("%s %s", fr.Path, darkBrackets(decorativeRisk(fr.RiskScore, fr.RiskLevel))),
		},
	)
	return nil
}

func (r Terminal) Full(ctx context.Context, rep *bincapz.Report) error {
	// Non-diff files are handled on the fly by File()
	if rep.Diff == nil {
		return nil
	}

	for f, fr := range rep.Diff.Removed {
		fr := fr
		renderTable(ctx, fr, r.w, tableConfig{
			Title:       fmt.Sprintf("Deleted: %s %s", f, darkBrackets(decorativeRisk(fr.RiskScore, fr.RiskLevel))),
			DiffRemoved: true,
		})
	}

	for f, fr := range rep.Diff.Added {
		fr := fr
		renderTable(ctx, fr, r.w, tableConfig{
			Title:     fmt.Sprintf("Added: %s %s", f, darkBrackets(decorativeRisk(fr.RiskScore, fr.RiskLevel))),
			DiffAdded: true,
		})
	}

	for f, fr := range rep.Diff.Modified {
		fr := fr
		var title string
		if fr.PreviousRelPath != "" {
			title = fmt.Sprintf("Moved: %s -> %s (score: %f)", fr.PreviousRelPath, f, fr.PreviousRelPathScore)
		} else {
			title = fmt.Sprintf("Changed: %s", f)
		}

		if fr.RiskScore != fr.PreviousRiskScore {
			title = fmt.Sprintf("%s %s\n\n", title,
				darkBrackets(fmt.Sprintf("%s %s %s", decorativeRisk(fr.PreviousRiskScore, fr.PreviousRiskLevel), color.HiWhiteString("→"), decorativeRisk(fr.RiskScore, fr.RiskLevel))))
		}

		fmt.Fprint(r.w, title)
		added := 0
		removed := 0
		for _, b := range fr.Behaviors {
			if b.DiffAdded {
				added++
			}
			if b.DiffRemoved {
				removed++
			}
		}

		if added > 0 {
			renderTable(ctx, fr, r.w, tableConfig{
				Title:       color.HiWhiteString("+++ ADDED: %d behavior(s) +++", added),
				SkipRemoved: true,
			})
		}

		if removed > 0 {
			renderTable(ctx, fr, r.w, tableConfig{
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
	cw := []string{}
	for _, w := range strings.Split(s, "\n") {
		cw = append(cw, color.HiBlackString(w))
	}
	return strings.Join(cw, "\n")
}

func renderTable(ctx context.Context, fr *bincapz.FileReport, w io.Writer, rc tableConfig) {
	title := rc.Title

	path := fr.Path
	if fr.Error != "" {
		fmt.Printf("⚠️ %s - error: %s\n", path, fr.Error)
		return
	}

	if fr.Skipped != "" {
		return
	}

	kbs := []KeyedBehavior{}
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

	data := [][]string{}

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

		risk := riskColor(ShortRisk(k.Behavior.RiskLevel))
		if k.Behavior.DiffAdded || rc.DiffAdded {
			if rc.SkipAdded {
				continue
			}
			risk = fmt.Sprintf("%s%s", color.HiWhiteString("+"), riskColor(ShortRisk(k.Behavior.RiskLevel)))
		}

		wKey := wrapKey(k.Key, keyWidth)
		wDesc := wrap(desc, descWidth)

		if k.Behavior.DiffRemoved || rc.DiffRemoved {
			if rc.SkipRemoved {
				continue
			}
			risk = fmt.Sprintf("%s%s", color.WhiteString("-"), riskColor(ShortRisk(k.Behavior.RiskLevel)))
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
