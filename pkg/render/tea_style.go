// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/charmbracelet/lipgloss"
)

var (
	roundedBorder = lipgloss.Border{
		Top:         "─",
		Bottom:      "─",
		Left:        "│",
		Right:       "│",
		TopLeft:     "╭",
		TopRight:    "╮",
		BottomLeft:  "╰",
		BottomRight: "╯",
	}

	fileBoxStyle = lipgloss.NewStyle().
			Border(roundedBorder).
			BorderForeground(lipgloss.Color("238")). // neutral gray
			Padding(0, 1)

	namespaceStyle = lipgloss.NewStyle().
			Bold(true).
			MarginLeft(2).
			MarginTop(1)

	behaviorStyle = lipgloss.NewStyle().
			MarginLeft(4)

	evidenceStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("246")).
			MarginLeft(6)

	riskColors = map[string]lipgloss.Color{
		report.LevelNONE:     lipgloss.Color("15"),
		report.LevelLOW:      lipgloss.Color("69"),
		report.LevelMEDIUM:   lipgloss.Color("221"),
		report.LevelHIGH:     lipgloss.Color("196"),
		report.LevelCRITICAL: lipgloss.Color("201"),
	}

	headerStyle = lipgloss.NewStyle().
			Bold(true)

	riskBadgeStyle = lipgloss.NewStyle().
			Padding(0, 1)

	diffAddedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("118"))

	diffRemovedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196"))

	riskChangeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("244"))
)

// cleanAndWrapEvidence handles evidence strings, including those with escape sequences.
func cleanAndWrapEvidence(evidence string, width int) string {
	// Split into separate strings if multiple are present
	lines := strings.Split(evidence, ", ")

	var result strings.Builder
	for i, line := range lines {
		if i > 0 {
			result.WriteString("\n")
		}
		result.WriteString("      ")

		unquoted, err := strconv.Unquote(`"` + line + `"`)
		if err != nil {
			// If unquoting fails, use original string
			unquoted = line
		}
		// Unquoting can turn an escape spelled out in the sample into a raw control byte.
		result.WriteString(wrapLine(sanitizeTerminal(unquoted), width))
	}

	return result.String()
}

// wrapLine breaks text into lines of at most width bytes, ending each on a
// character boundary, and indents each continuation line. A character longer
// than width gets a line of its own. Text that fits is returned as is,
// without copying it.
func wrapLine(text string, width int) string {
	if len(text) <= width {
		return text
	}

	var result strings.Builder
	for len(text) > width {
		n := width
		for n > 0 && !utf8.RuneStart(text[n]) {
			n--
		}
		if n == 0 {
			_, n = utf8.DecodeRuneInString(text)
		}
		if n >= len(text) {
			break
		}
		result.WriteString(text[:n])
		result.WriteString("\n      ")
		text = text[n:]
	}
	result.WriteString(text)
	return result.String()
}

// teaBadge renders level, escaped by sanitizeTerminal, in its risk color.
func teaBadge(level string) string {
	return riskBadgeStyle.Foreground(riskColors[level]).Render(sanitizeTerminal(level))
}

// teaHeader renders the first line of a file summary: text, which the caller
// escapes, in the color of level, then a badge for level.
func teaHeader(text, level string) string {
	return lipgloss.JoinHorizontal(lipgloss.Center, headerStyle.Foreground(riskColors[level]).Render(text), " ", teaBadge(level))
}

// teaScanHeader returns the header of a scanned file: its path and risk level.
func teaScanHeader(fr *malcontent.FileReport) string {
	return teaHeader(sanitizeTerminal(fr.Path), fr.RiskLevel)
}

// teaChangeHeader renders the first line of a file summary whose risk
// changed: text in the color of level, then the change from previous to level.
func teaChangeHeader(text, previous, level string) string {
	change := riskChangeStyle.Render(teaBadge(previous) + " → " + teaBadge(level))
	return lipgloss.JoinHorizontal(lipgloss.Center, headerStyle.Foreground(riskColors[level]).Render(text), " ", change)
}

// teaDiffHeader returns the header of a modified file in a diff, with its
// diff counts, its previous path if it moved, and its risk change if any.
func teaDiffHeader(fr *malcontent.FileReport, added, removed int) string {
	title := diffTitle(fr, added, removed, sanitizeTerminal)
	if fr.RiskScore != fr.PreviousRiskScore {
		return teaChangeHeader(title, fr.PreviousRiskLevel, fr.RiskLevel)
	}
	return teaHeader(title, fr.RiskLevel)
}

// renderFileSummaryTea writes header, which the caller builds, and fr's
// listed behaviors, grouped by namespace, in a box for the interactive
// viewer. A diff lists only added and removed behaviors. Each namespace
// shows the highest risk among the behaviors listed under it.
func renderFileSummaryTea(ctx context.Context, fr *malcontent.FileReport, header string, w io.Writer) {
	if ctx.Err() != nil || fr.Skipped != "" {
		return
	}

	// Organize the listed behaviors by namespace
	diffMode := isDiffMode(fr.Behaviors)
	byNamespace := map[string][]*malcontent.Behavior{}
	nsRiskScore := map[string]int{}
	for _, b := range fr.Behaviors {
		if !listedBehavior(b, diffMode) {
			continue
		}
		ns, _ := splitRuleID(b.ID)
		byNamespace[ns] = append(byNamespace[ns], b)
		nsRiskScore[ns] = max(nsRiskScore[ns], b.RiskScore)
	}

	// Sort namespaces by long name; distinct namespaces with the same long
	// name keep a fixed order.
	nss := slices.SortedFunc(maps.Keys(byNamespace), func(a, b string) int {
		return cmp.Or(cmp.Compare(nsLongName(a), nsLongName(b)), cmp.Compare(a, b))
	})

	// Build the complete content
	var content strings.Builder
	content.WriteString(header)
	content.WriteString("\n")

	// Render namespace sections
	for _, ns := range nss {
		riskLevel := riskLevels[nsRiskScore[ns]]
		nsHeader := sanitizeTerminal(nsLongName(ns)) + " " + teaBadge(riskLevel)
		content.WriteString(namespaceStyle.Foreground(riskColors[riskLevel]).Render(nsHeader))
		content.WriteString("\n")

		// Render behaviors
		for _, b := range byNamespace[ns] {
			// Style behavior based on risk level and diff status
			baseStyle := behaviorStyle.
				Foreground(riskColors[b.RiskLevel])

			bullet := "•"
			showEvidence := true

			if diffMode {
				switch {
				case b.DiffAdded:
					bullet = "+"
					baseStyle = diffAddedStyle
				case b.DiffRemoved:
					bullet = "-"
					baseStyle = diffRemovedStyle
					showEvidence = false
				}
			}

			_, rest := splitRuleID(b.ID)
			var e string
			if showEvidence {
				e = evidenceString(b.MatchStrings, b.Description)
			}
			desc, _, _ := strings.Cut(b.Description, " - ")

			if b.RuleAuthor != "" {
				if desc != "" {
					desc += ", by " + b.RuleAuthor
				} else {
					desc = "by " + b.RuleAuthor
				}
			}

			// Add risk level badge to behavior
			behaviorRisk := riskBadgeStyle.
				Foreground(riskColors[b.RiskLevel]).
				Render(sanitizeTerminal(ShortRisk(b.RiskLevel)))

			content.WriteString(baseStyle.Render(bullet + " " + behaviorRisk + " " + sanitizeTerminal(rest) + " " + sanitizeTerminal(desc)))
			content.WriteString("\n")

			// Add evidence if present
			if e != "" {
				formattedEvidence := cleanAndWrapEvidence(e, 70) // Adjust width as needed
				content.WriteString(evidenceStyle.Render(formattedEvidence))
				content.WriteString("\n")
			}
		}
	}

	// Render the complete file box
	fmt.Fprintln(w, fileBoxStyle.Render(content.String()))
	fmt.Fprintln(w)
}
