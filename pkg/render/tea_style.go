// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

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

// wrapLine breaks text into lines of width bytes, indenting each
// continuation line. Text that fits is returned as is, without copying it.
func wrapLine(text string, width int) string {
	if len(text) <= width {
		return text
	}

	var result strings.Builder
	for len(text) > width {
		result.WriteString(text[:width])
		result.WriteString("\n      ")
		text = text[width:]
	}
	result.WriteString(text)
	return result.String()
}

// renderFileSummaryTea writes fr's behaviors, grouped by namespace, in a box
// for the interactive viewer. A file with added or removed behaviors gets a
// title that counts them.
func renderFileSummaryTea(ctx context.Context, fr *malcontent.FileReport, w io.Writer) {
	if ctx.Err() != nil || fr.Skipped != "" {
		return
	}

	// Organize behaviors by namespace
	byNamespace := map[string][]*malcontent.Behavior{}
	nsRiskScore := map[string]int{}
	previousNsRiskScore := map[string]int{}
	diffMode := false

	var added, removed int
	for _, b := range fr.Behaviors {
		ns, _ := splitRuleID(b.ID)
		if b.DiffAdded || b.DiffRemoved {
			diffMode = true
		}
		if !b.DiffAdded && b.RiskScore > previousNsRiskScore[ns] {
			previousNsRiskScore[ns] = b.RiskScore
		}
		byNamespace[ns] = append(byNamespace[ns], b)
		if !b.DiffRemoved {
			nsRiskScore[ns] = max(nsRiskScore[ns], b.RiskScore)
		}

		if b.DiffAdded {
			added++
		}
		if b.DiffRemoved {
			removed++
		}
	}

	// Sort namespaces
	nss := make([]string, 0, len(byNamespace))
	for ns := range byNamespace {
		nss = append(nss, ns)
	}
	slices.SortFunc(nss, func(a, b string) int {
		return cmp.Compare(nsLongName(a), nsLongName(b))
	})

	// Build the complete content
	var content strings.Builder

	// File header with risk level
	path := sanitizeTerminal(fr.Path)
	pathStyle := headerStyle.
		Foreground(riskColors[fr.RiskLevel])

	riskBadge := riskBadgeStyle.
		Foreground(riskColors[fr.RiskLevel]).
		Render(fr.RiskLevel)

	header := lipgloss.JoinHorizontal(
		lipgloss.Center,
		pathStyle.Render(path),
		" ",
		riskBadge,
	)

	if diffMode {
		title := fmt.Sprintf("Changed (%d added, %d removed): %s", added, removed, path)
		header = lipgloss.JoinHorizontal(
			lipgloss.Center,
			pathStyle.Render(title),
			" ",
			riskBadge,
		)
	}

	content.WriteString(header)
	content.WriteString("\n")

	// Render namespace sections
	for _, ns := range nss {
		bs := byNamespace[ns]
		riskScore := nsRiskScore[ns]
		riskLevel := riskLevels[riskScore]

		// Namespace header
		nsHeader := nsLongName(ns)
		if len(previousNsRiskScore) > 0 && riskScore != previousNsRiskScore[ns] {
			previousRiskLevel := riskLevels[previousNsRiskScore[ns]]
			transition := riskBadgeStyle.Foreground(riskColors[previousRiskLevel]).Render(previousRiskLevel) +
				" → " +
				riskBadgeStyle.Foreground(riskColors[riskLevel]).Render(riskLevel)
			nsHeader += " " + riskChangeStyle.Render(transition)
		} else {
			nsHeader += " " + riskBadgeStyle.Foreground(riskColors[riskLevel]).Render(riskLevel)
		}

		nsStyle := namespaceStyle.Foreground(riskColors[riskLevel]).Render(nsHeader)
		content.WriteString(nsStyle)
		content.WriteString("\n")

		// Render behaviors
		for _, b := range bs {
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
				default:
					continue
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
				Render(ShortRisk(b.RiskLevel))

			content.WriteString(baseStyle.Render(bullet + " " + behaviorRisk + " " + rest + " " + desc))
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
