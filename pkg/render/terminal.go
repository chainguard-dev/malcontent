// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
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
	SkipAdded    bool
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
		renderFileSummary(ctx, fr, r.w,
			tableConfig{
				Title: fmt.Sprintf("%s %s", fr.Path, darkBrackets(riskInColor(fr.RiskLevel))),
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
		renderFileSummary(ctx, removed.Value, r.w, tableConfig{
			Title:       fmt.Sprintf("Deleted: %s %s", removed.Key, darkBrackets(riskInColor(removed.Value.RiskLevel))),
			DiffRemoved: true,
		})
	}

	for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
		renderFileSummary(ctx, added.Value, r.w, tableConfig{
			Title:     fmt.Sprintf("Added: %s %s", added.Key, darkBrackets(riskInColor(added.Value.RiskLevel))),
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
			title = fmt.Sprintf("%s %s", title,
				darkBrackets(fmt.Sprintf("%s %s %s", riskInColor(modified.Value.PreviousRiskLevel), color.HiWhiteString("→"), riskInColor(modified.Value.RiskLevel))))
		}

		renderFileSummary(ctx, modified.Value, r.w, tableConfig{Title: title})
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
	rest := strings.Join(parts[1:], "/")
	return parts[0], rest
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

func renderFileSummary(_ context.Context, fr *malcontent.FileReport, w io.Writer, rc tableConfig) {
	fmt.Fprintf(w, "├─ %s %s\n", riskEmoji(fr.RiskScore), rc.Title)
	width := suggestedWidth()

	byNamespace := map[string][]*malcontent.Behavior{}
	nsRiskScore := map[string]int{}
	previousNsRiskScore := map[string]int{}
	diffMode := false

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

		if b.DiffRemoved {
			continue
		}

		if b.RiskScore > nsRiskScore[ns] {
			nsRiskScore[ns] = b.RiskScore
		}
	}

	nss := []string{}
	for ns := range byNamespace {
		nss = append(nss, ns)
	}

	// sort by the long names as that's how they'll be displayed later
	sort.Slice(nss, func(i, j int) bool {
		return nsLongName(nss[i]) < nsLongName(nss[j])
	})

	for _, ns := range nss {
		bs := byNamespace[ns]
		riskScore := nsRiskScore[ns]
		riskLevel := riskLevels[riskScore]
		nsIcon := "≡"
		indent := "     "

		// namespace readout
		if len(previousNsRiskScore) > 0 && riskScore != previousNsRiskScore[ns] {
			previousRiskLevel := riskLevels[previousNsRiskScore[ns]]
			if riskLevel < previousRiskLevel {
				nsIcon = color.HiYellowString("▲")
			}
			if riskLevel > previousRiskLevel {
				nsIcon = color.HiGreenString("▼")
			}
			if riskLevel == "NONE" {
				nsIcon = color.RedString("X")
			}

			fmt.Fprintf(w, "│%s%s %s %s\n", indent, nsIcon, nsLongName(ns), darkBrackets(fmt.Sprintf("%s → %s", riskInColor(previousRiskLevel), riskInColor(riskLevel))))
		} else {
			fmt.Fprintf(w, "│%s%s %s %s\n", indent, nsIcon, nsLongName(ns), darkBrackets(riskInColor(riskLevel)))
		}

		// behavior readout per namespace
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

			prefix := "│  "
			bullet := riskEmoji(b.RiskScore)
			content := fmt.Sprintf("%s%s%s %s", prefix, indent, riskColor(b.RiskLevel, bullet+" "+rest), desc)
			pc := color.New()

			if diffMode {
				content = fmt.Sprintf("%s%s%s %s %s", prefix, indent, bullet, rest, desc)

				if b.DiffAdded {
					pc = color.New(color.FgHiGreen)
					prefix = "+++"
					content = fmt.Sprintf("%s%s%s %s %s", prefix, indent, bullet, rest, desc)
				}

				if b.DiffRemoved {
					prefix = "---"
					pc = color.New(color.FgHiRed)
					content = fmt.Sprintf("%s%s%s %s %s", prefix, indent, bullet, rest, desc)
					e = ""
				}
			}

			// no evidence to give
			if e == "" {
				pc.Fprintln(w, content+e)
				continue
			}

			pc.Fprint(w, content)
			color.New(color.FgHiBlack).Fprint(w, ":")
			e = color.RGB(255, 255, 255).Sprint(e)

			// Two-line output for long evidence strings
			if ansiLineLength(content+e)+1 > width && len(e) > 4 {
				pc.Fprintln(w, "\n"+truncate(fmt.Sprintf("%s           %s", prefix, e), width))
				continue
			}
			// Single-line output for short evidence
			pc.Fprintln(w, " "+e)
		}
	}
	fmt.Fprintf(w, "│\n")
}
