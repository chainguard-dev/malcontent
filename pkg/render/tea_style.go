package render

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
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
		"NONE":     lipgloss.Color("15"),
		"LOW":      lipgloss.Color("69"),
		"MEDIUM":   lipgloss.Color("221"),
		"HIGH":     lipgloss.Color("196"),
		"CRITICAL": lipgloss.Color("201"),
	}

	headerStyle = lipgloss.NewStyle().
			Bold(true)

	riskBadgeStyle = lipgloss.NewStyle().
			Padding(0, 1)

	diffAddedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("118"))

	diffRemovedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196"))
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

		if len(unquoted) > width {
			wrapped := wrapLine(unquoted, width)
			result.WriteString(wrapped)
		} else {
			result.WriteString(unquoted)
		}
	}

	return result.String()
}

// wrapLine wraps a single line of text.
func wrapLine(text string, width int) string {
	if len(text) <= width {
		return text
	}

	var result strings.Builder
	remaining := text
	firstLine := true

	for len(remaining) > 0 {
		if !firstLine {
			result.WriteString("\n      ") // indent continuation lines
		}

		chunk := remaining
		if len(remaining) > width {
			chunk = remaining[:width]
			remaining = remaining[width:]
		} else {
			remaining = ""
		}

		result.WriteString(chunk)
		firstLine = false
	}

	return result.String()
}

func renderFileSummaryTea(ctx context.Context, fr *malcontent.FileReport, w io.Writer, rc tableConfig) {
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
		if !b.DiffRemoved && b.RiskScore > nsRiskScore[ns] {
			nsRiskScore[ns] = b.RiskScore
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
	sort.Slice(nss, func(i, j int) bool {
		return nsLongName(nss[i]) < nsLongName(nss[j])
	})

	// Build the complete content
	var content strings.Builder

	// File header with risk level
	pathStyle := headerStyle.
		Foreground(riskColors[fr.RiskLevel])

	riskBadge := riskBadgeStyle.
		Foreground(riskColors[fr.RiskLevel]).
		Render(fr.RiskLevel)

	header := lipgloss.JoinHorizontal(
		lipgloss.Center,
		pathStyle.Render(fr.Path),
		" ",
		riskBadge,
	)

	if added == 0 && removed == 0 {
		return
	}

	if diffMode {
		rc.Title = fmt.Sprintf("Changed (%d added, %d removed): %s", added, removed, fr.Path)
		header = lipgloss.JoinHorizontal(
			lipgloss.Center,
			pathStyle.Render(rc.Title),
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
			riskChangeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
			nsHeader = fmt.Sprintf("%s %s",
				nsHeader,
				riskChangeStyle.Render(fmt.Sprintf("%s → %s",
					riskBadgeStyle.Foreground(riskColors[previousRiskLevel]).Render(previousRiskLevel),
					riskBadgeStyle.Foreground(riskColors[riskLevel]).Render(riskLevel))))
		} else {
			badgeStyle := riskBadgeStyle.Foreground(riskColors[riskLevel]).Render(riskLevel)
			nsHeader = fmt.Sprintf("%s %s",
				nsHeader,
				badgeStyle)
		}

		nsStyle := namespaceStyle.Foreground(riskColors[riskLevel]).Render(nsHeader)
		content.WriteString(nsStyle)
		content.WriteString("\n")

		// Render behaviors
		for _, b := range bs {
			_, rest := splitRuleID(b.ID)
			e := evidenceString(b.MatchStrings, b.Description)
			desc, _, _ := strings.Cut(b.Description, " - ")

			if b.RuleAuthor != "" {
				if desc != "" {
					desc = fmt.Sprintf("%s, by %s", desc, b.RuleAuthor)
				} else {
					desc = fmt.Sprintf("by %s", b.RuleAuthor)
				}
			}

			// Style behavior based on risk level and diff status
			baseStyle := behaviorStyle.
				Foreground(riskColors[b.RiskLevel])

			bullet := "•"

			if diffMode {
				switch {
				case b.DiffAdded:
					bullet = "+"
					baseStyle = diffAddedStyle
				case b.DiffRemoved:
					bullet = "-"
					baseStyle = diffRemovedStyle
					e = ""
				default:
					continue
				}
			}

			// Add risk level badge to behavior
			behaviorRisk := riskBadgeStyle.
				Foreground(riskColors[b.RiskLevel]).
				Render(ShortRisk(b.RiskLevel))

			content.WriteString(baseStyle.Render(fmt.Sprintf("%s %s %s %s",
				bullet,
				behaviorRisk,
				rest,
				desc)))
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
