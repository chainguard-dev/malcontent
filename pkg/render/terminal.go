package render

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/term"
	"k8s.io/klog/v2"
)

// ignoreMeta are fields to ignore in output.
var ignoreMeta = map[string]bool{
	"format": true,
}

type KeyedBehavior struct {
	Key      string
	Behavior bincapz.Behavior
}

type tableConfig struct {
	Title       string
	ShowTitle   bool
	DiffRemoved bool
	DiffAdded   bool
}

func forceWrap(s string, x int) string {
	words, _ := tablewriter.WrapString(s, x)
	fw := []string{}
	for _, w := range words {
		if len(w) > x-2 {
			klog.Infof("wrapping %s - longer than %d", w, x-2)
			w = w[0:x-2] + ".."
		}
		fw = append(fw, w)
	}
	return strings.Join(fw, "\n")
}

func terminalWidth() int {
	if !term.IsTerminal(0) {
		return 120
	}

	width, _, err := term.GetSize(0)
	if err != nil {
		klog.Errorf("term.getsize: %v", err)
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
	symbol := "✅"
	switch score {
	case 3:
		symbol = "🔥"
	case 4:
		symbol = "🚨"
	}

	return fmt.Sprintf("%s %d/%s", symbol, score, level)
}

func shortRisk(s string) string {
	if len(s) < 4 {
		return s
	}
	short := s[0:4]
	if s == "MEDIUM" {
		return "MED"
	}
	return short
}

func (r Terminal) File(fr bincapz.FileReport) error {
	renderTable(&fr, r.w,
		tableConfig{
			Title: fmt.Sprintf("Path: %s\nRisk: %s", fr.Path, decorativeRisk(fr.RiskScore, fr.RiskLevel)),
		},
	)
	return nil
}

func (r Terminal) Full(rep bincapz.Report) error {
	for f, fr := range rep.Diff.Removed {
		fr := fr
		renderTable(&fr, r.w, tableConfig{
			Title:       fmt.Sprintf("➖ Deleted: %s", f),
			DiffRemoved: true,
		})
	}

	for f, fr := range rep.Diff.Added {
		fr := fr
		renderTable(&fr, r.w, tableConfig{
			Title:     fmt.Sprintf("Added: %s\nAdded Risk: %s", f, decorativeRisk(fr.RiskScore, fr.RiskLevel)),
			DiffAdded: true,
		})
	}

	for _, fr := range rep.Diff.Modified {
		fr := fr
		title := fmt.Sprintf("Changed: %s", fr.Path)
		if fr.RiskScore != fr.PreviousRiskScore {
			title = fmt.Sprintf("%s\nPrevious Risk: %s\nNew Risk:      %s",
				title,
				decorativeRisk(fr.PreviousRiskScore, fr.PreviousRiskLevel),
				decorativeRisk(fr.RiskScore, fr.RiskLevel))
		}
		renderTable(&fr, r.w, tableConfig{
			Title: title,
		})
	}
	return nil
}

func renderTable(fr *bincapz.FileReport, w io.Writer, rc tableConfig) {
	title := rc.Title

	path := fr.Path
	if fr.Error != "" {
		fmt.Printf("⚠️ %s - error: %s\n", path, fr.Error)
		return
	}

	if fr.Skipped != "" {
		// fmt.Printf("%s - skipped: %s\n", path, fr.Skipped)
		return
	}

	kbs := []KeyedBehavior{}
	for k, b := range fr.Behaviors {
		kbs = append(kbs, KeyedBehavior{Key: k, Behavior: b})
	}

	if len(kbs) == 0 {
		return
	}

	sort.Slice(kbs, func(i, j int) bool {
		if kbs[i].Behavior.RiskScore == kbs[j].Behavior.RiskScore {
			return kbs[i].Key < kbs[j].Key
		}
		return kbs[i].Behavior.RiskScore > kbs[j].Behavior.RiskScore
	})

	data := [][]string{}

	for k, v := range fr.Meta {
		if ignoreMeta[k] {
			data = append(data, []string{"meta", k, v})
		}
	}

	tWidth := terminalWidth()
	keyWidth := 36
	riskWidth := 7
	padding := 6
	maxKeyLen := 0

	for _, k := range kbs {
		key := forceWrap(k.Key, keyWidth)
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
	}

	descWidth := tWidth - maxKeyLen - riskWidth - padding
	if descWidth > 120 {
		descWidth = 120
	}

	klog.Infof("terminal width: %d - desc width: %d", tWidth, descWidth)

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

		key := forceWrap(k.Key, keyWidth)
		words, _ := tablewriter.WrapString(desc, descWidth)

		//		klog.Infof("%s / %s - %s", k.Key, desc, k.Behavior.)
		desc = strings.Join(words, "\n")
		if len(k.Behavior.Values) > 0 {
			klog.Infof("VALUES: %s", k.Behavior.Values)
			values := strings.Join(k.Behavior.Values, "\n")
			before := " \""
			after := "\""
			if (len(desc) + len(values) + 3) > descWidth {
				before = "\n"
				after = ""
			}
			desc = fmt.Sprintf("%s:%s%s%s", desc, before, forceWrap(strings.Join(k.Behavior.Values, "\n"), descWidth), after)
		}

		// lowercase first character for consistency
		desc = strings.ToLower(string(desc[0])) + desc[1:]
		risk := fmt.Sprintf("%d/%s", k.Behavior.RiskScore, shortRisk(k.Behavior.RiskLevel))
		if k.Behavior.DiffAdded || rc.DiffAdded {
			risk = fmt.Sprintf("+%s", risk)
		}
		if k.Behavior.DiffRemoved || rc.DiffRemoved {
			risk = fmt.Sprintf("-%s", risk)
		}

		data = append(data, []string{risk, key, desc})
	}

	if title != "" {
		fmt.Fprintf(w, "%s\n", title)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	table.SetBorder(false)
	table.SetCenterSeparator("")
	maxDescWidth := 0
	maxRiskWidth := 0
	for _, d := range data {
		if len(d[0]) > maxRiskWidth {
			maxRiskWidth = len(d[0])
		}
		for _, l := range strings.Split(d[2], "\n") {
			if len(l) > maxDescWidth {
				maxDescWidth = len(l)
			}
		}
	}

	tableWidth := maxKeyLen + maxDescWidth + padding + maxRiskWidth
	klog.Infof("table width: %d", tableWidth)
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", tableWidth))
	table.SetNoWhiteSpace(true)
	table.SetTablePadding("  ")
	descColor := tablewriter.Normal

	for _, d := range data {
		keyColor := tablewriter.Normal
		riskColor := tablewriter.Normal

		if strings.HasPrefix(d[0], "+") {
			keyColor = tablewriter.FgHiWhiteColor
		}
		if strings.HasPrefix(d[0], "-") {
			keyColor = tablewriter.FgHiBlackColor
		}

		if strings.Contains(d[0], "LOW") {
			riskColor = tablewriter.FgGreenColor
			if strings.HasPrefix(d[0], "+") {
				riskColor = tablewriter.FgHiGreenColor
			}
		}

		if strings.Contains(d[0], "MED") {
			riskColor = tablewriter.FgYellowColor
			if strings.HasPrefix(d[0], "-") {
				riskColor = tablewriter.FgHiYellowColor
			}
		}

		if strings.Contains(d[0], "HIGH") {
			riskColor = tablewriter.FgRedColor
			if strings.HasPrefix(d[0], "+") {
				riskColor = tablewriter.FgHiRedColor
			}
		}
		if strings.Contains(d[0], "CRIT") {
			riskColor = tablewriter.FgMagentaColor
			if strings.HasPrefix(d[0], "+") {
				riskColor = tablewriter.FgHiMagentaColor
			}
		}

		table.Rich(d, []tablewriter.Colors{{riskColor}, {keyColor}, {descColor}})

		//		table.Append(d)
	}
	table.Render()
	fmt.Fprintf(w, "\n")
}
