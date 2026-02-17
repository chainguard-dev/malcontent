// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/fatih/color"
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

type Terminal struct {
	w io.Writer
}

func NewTerminal(w io.Writer) Terminal {
	return Terminal{w: w}
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
		return color.HiCyanString(text)
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
	switch s {
	case "CRITICAL":
		return "CRIT"
	case "MEDIUM":
		return "MED"
	case "HIGH", "LOW", "NONE":
		return s
	default:
		return s
	}
}

func (r Terminal) Name() string { return "Terminal" }

func (r Terminal) Scanning(_ context.Context, path string) {
	fmt.Fprintf(r.w, "🔎 Scanning %q\n", path)
}

func (r Terminal) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr.Skipped == "" && len(fr.Behaviors) > 0 {
		renderFileSummary(ctx, fr, r.w,
			tableConfig{
				Title: fmt.Sprintf("%s %s", fr.Path, darkBrackets(riskInColor(fr.RiskLevel))),
			},
			false,
		)
	}
	return nil
}

func (r Terminal) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// guard against nil reports
	// Non-diff files are handled on the fly by File()
	if rep == nil || rep.Diff == nil {
		return nil
	}

	for removed := rep.Diff.Removed.Oldest(); removed != nil; removed = removed.Next() {
		if len(removed.Value.Behaviors) == 0 {
			continue
		}

		renderFileSummary(ctx, removed.Value, r.w, tableConfig{
			Title:       fmt.Sprintf(riskColor(removed.Value.RiskLevel, "Deleted: %s %s"), removed.Key, darkBrackets(riskInColor(removed.Value.RiskLevel))),
			DiffRemoved: true,
		}, false)
	}

	for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
		if len(added.Value.Behaviors) == 0 {
			continue
		}

		renderFileSummary(ctx, added.Value, r.w, tableConfig{
			Title:     fmt.Sprintf(riskColor(added.Value.RiskLevel, "Added: %s %s"), added.Key, darkBrackets(riskInColor(added.Value.RiskLevel))),
			DiffAdded: true,
		}, false)
	}

	for modified := rep.Diff.Modified.Oldest(); modified != nil; modified = modified.Next() {
		if len(modified.Value.Behaviors) == 0 {
			continue
		}

		// Count added and removed behaviors
		var added, removed int
		for _, b := range modified.Value.Behaviors {
			if b.DiffAdded {
				added++
			}
			if b.DiffRemoved {
				removed++
			}
		}

		if added == 0 && removed == 0 {
			continue
		}

		var moved bool
		var title string
		if modified.Value.PreviousPath != "" {
			moved = true
			title = fmt.Sprintf(riskColor(modified.Value.PreviousRiskLevel, "Moved (%d added, %d removed): %s -> %s"), added, removed, modified.Value.PreviousPath, modified.Value.Path)
		} else {
			title = fmt.Sprintf(riskColor(modified.Value.RiskLevel, "Changed (%d added, %d removed): %s"), added, removed, modified.Value.Path)
			if modified.Value.RiskScore != modified.Value.PreviousRiskScore {
				title = fmt.Sprintf("%s %s", title,
					darkBrackets(fmt.Sprintf("%s %s %s", riskInColor(modified.Value.PreviousRiskLevel), color.HiWhiteString("→"), riskInColor(modified.Value.RiskLevel))))
			}
		}

		renderFileSummary(ctx, modified.Value, r.w, tableConfig{Title: title}, moved)
	}

	return nil
}

// generate a good looking evidence string.
func evidenceString(ms []string, desc string) string {
	evidence := []string{}
	for _, m := range ms {
		if len(m) > 2 && !strings.Contains(desc, m) {
			evidence = append(evidence, m)
		}
	}

	return strings.Join(evidence, ", ")
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
	parts := strings.Split(s, "/")
	var id, rest string
	if len(parts) > 0 {
		id = parts[0]
		if len(parts) > 1 {
			rest = strings.Join(parts[1:], "/")
		}
	}
	return id, rest
}

// suggestedWidth calculates a maximum terminal width to render against.
func suggestedWidth() int {
	if !term.IsTerminal(0) {
		return 160
	}

	width, _, err := term.GetSize(0)
	if err != nil {
		return 160
	}

	if width < 75 {
		width = 75
	}

	return width
}

// truncate truncates a string with ellipsis.
func truncate(s string, i int) string {
	if len(s) > i {
		return s[0:i-1] + "…"
	}
	return s
}

// ansiLineLength determines the length of a line, even if it has ANSI codes.
func ansiLineLength(s string) int {
	re := regexp.MustCompile(`\x1b\[[0-9;]*[mG]`)
	clean := re.ReplaceAllString(s, "")
	return len(clean)
}

func renderFileSummary(ctx context.Context, fr *malcontent.FileReport, w io.Writer, rc tableConfig, moved bool) {
	if ctx.Err() != nil {
		return
	}

	width := suggestedWidth()

	byNamespace := map[string][]*malcontent.Behavior{}
	nsRiskScore := map[string]int{}
	previousNsRiskScore := map[string]int{}
	diffMode := false

	if fr.Skipped != "" {
		return
	}

	var added, removed int
	for _, b := range fr.Behaviors {
		ns, _ := splitRuleID(b.ID)

		if b.DiffAdded || b.DiffRemoved {
			diffMode = true
		}

		if !b.DiffAdded {
			if b.RiskScore > previousNsRiskScore[ns] {
				previousNsRiskScore[ns] = b.RiskScore
			}
		}

		byNamespace[ns] = append(byNamespace[ns], b)

		if b.DiffAdded {
			added++
		}
		if b.DiffRemoved {
			removed++
		}

		if b.RiskScore > nsRiskScore[ns] {
			nsRiskScore[ns] = b.RiskScore
		}

		if added == 0 && removed == 0 {
			continue
		}

		if !moved && diffMode {
			rc.Title = fmt.Sprintf(riskColor(fr.RiskLevel, "Changed (%d added, %d removed): %s"), added, removed, fr.Path)
		}
	}

	fmt.Fprintf(w, "├─ %s %s\n", riskEmoji(fr.RiskScore), rc.Title)

	for _, ns := range slices.SortedFunc(maps.Keys(byNamespace), func(i, j string) int {
		return len(nsLongName(i)) - len(nsLongName(j))
	}) {
		bs := byNamespace[ns]
		riskScore := nsRiskScore[ns]
		riskLevel := riskLevels[riskScore]
		nsIcon := "≡"
		indent := "    "
		diff := " "

		// namespace readout
		if len(previousNsRiskScore) > 0 && riskScore != previousNsRiskScore[ns] {
			previousRiskLevel := riskLevels[previousNsRiskScore[ns]]
			if previousRiskLevel == "NONE" {
				diff = color.HiGreenString("+")
			}

			if riskScore > previousNsRiskScore[ns] {
				nsIcon = color.HiYellowString("▲")
			}
			if riskScore < previousNsRiskScore[ns] {
				nsIcon = color.HiGreenString("▼")
			}
			if riskLevel == "NONE" {
				diff = color.HiRedString("-")
			}

			fmt.Fprintf(w, "│%s%s%s %s %s\n", diff, indent, nsIcon, nsLongName(ns), darkBrackets(fmt.Sprintf("%s → %s", riskInColor(previousRiskLevel), riskInColor(riskLevel))))
		} else {
			fmt.Fprintf(w, "│%s%s%s %s %s\n", diff, indent, nsIcon, nsLongName(ns), darkBrackets(riskInColor(riskLevel)))
		}

		// behavior readout per namespace
		indent += "  "
		for _, b := range bs {
			_, rest := splitRuleID(b.ID)

			e := evidenceString(b.MatchStrings, b.Description)
			desc, _, _ := strings.Cut(b.Description, " - ")
			desc = "— " + desc

			if b.RuleAuthor != "" {
				if desc != "" {
					desc = fmt.Sprintf("%s, by %s", desc, b.RuleAuthor)
				} else {
					desc = fmt.Sprintf("by %s", b.RuleAuthor)
				}
			}

			bullet := riskEmoji(b.RiskScore)
			diff := " "
			content := fmt.Sprintf("%s%s%s %s", diff, indent, riskColor(b.RiskLevel, bullet+" "+rest), desc)
			pc := color.New()

			if diffMode {
				if b.DiffAdded {
					pc = color.New(color.FgHiGreen)
					diff = "+"
				}

				if b.DiffRemoved {
					diff = "-"
					pc = color.New(color.FgHiRed)
					e = ""
				}

				if !b.DiffAdded && !b.DiffRemoved {
					continue
				}

				content = fmt.Sprintf("%s%s%s %s %s", diff, indent, bullet, rest, desc)
			}

			prefix := "│"
			// no evidence to give
			if e == "" {
				fmt.Fprint(w, prefix)
				pc.Fprintln(w, content)
				continue
			}

			fmt.Fprint(w, prefix)
			pc.Fprint(w, content)
			color.New(color.FgHiBlack).Fprint(w, ":")
			e = color.RGB(255, 255, 255).Sprint(e)

			// Two-line output for long evidence strings
			if ansiLineLength(content+e)+1 > width && len(e) > 4 {
				pc.Fprintln(w, "\n"+truncate(fmt.Sprintf("%s%s         %s", prefix, diff, e), width))
				continue
			}
			// Single-line output for short evidence
			pc.Fprintln(w, " "+e)
		}
	}
	fmt.Fprintf(w, "│\n")
}
