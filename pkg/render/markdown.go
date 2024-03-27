package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/olekukonko/tablewriter"
	"k8s.io/klog/v2"
)

type Markdown struct {
	w io.Writer
}

func NewMarkdown(w io.Writer) Markdown {
	return Markdown{w: w}
}

func (r Markdown) File(fr bincapz.FileReport) error {
	markdownTable(&fr, r.w, tableConfig{Title: fmt.Sprintf("## %s\n\nOverall risk: %s", fr.Path, decorativeRisk(fr.RiskScore, fr.RiskLevel))})
	return nil
}

func (r Markdown) Full(rep bincapz.Report) error {
	for f, fr := range rep.Diff.Removed {
		fr := fr
		markdownTable(&fr, r.w, tableConfig{Title: fmt.Sprintf("## Deleted: %s", f), DiffRemoved: true})
	}

	for f, fr := range rep.Diff.Added {
		fr := fr
		markdownTable(&fr, r.w, tableConfig{Title: fmt.Sprintf("## Added: %s\n\nOverall risk: %s", f, decorativeRisk(fr.RiskScore, fr.RiskLevel)), DiffAdded: true})
	}

	for _, fr := range rep.Diff.Modified {
		fr := fr
		title := fmt.Sprintf("## Modified: %s\n", fr.Path)
		if fr.RiskScore != fr.PreviousRiskScore {
			title = fmt.Sprintf("%s\nPrevious Risk: %s\nNew Risk:      %s",
				title,
				decorativeRisk(fr.PreviousRiskScore, fr.PreviousRiskLevel),
				decorativeRisk(fr.RiskScore, fr.RiskLevel))
		}

		markdownTable(&fr, r.w, tableConfig{Title: title})
	}
	return nil
}

func markdownTable(fr *bincapz.FileReport, w io.Writer, rc tableConfig) {
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

	for k, v := range fr.Meta {
		data = append(data, []string{"meta", k, v})
	}
	if len(data) > 0 {
		data = append(data, []string{"", "", ""})
	}

	maxDescWidth := 180
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

		if len(k.Behavior.Values) > 0 {
			klog.Infof("VALUES: %s", k.Behavior.Values)
			values := strings.Join(k.Behavior.Values, "\n")
			before := " \""
			after := "\""
			if (len(desc) + len(values) + 3) > maxDescWidth {
				before = "\n"
				after = ""
			}
			desc = fmt.Sprintf("%s:%s%s%s", desc, before, strings.Join(k.Behavior.Values, "\n"), after)
		}

		// lowercase first character for consistency
		desc = strings.ToLower(string(desc[0])) + desc[1:]
		risk := fmt.Sprintf("%d/%s", k.Behavior.RiskScore, k.Behavior.RiskLevel)
		if k.Behavior.DiffAdded || rc.DiffAdded {
			risk = fmt.Sprintf("+%s", risk)
		}
		if k.Behavior.DiffRemoved || rc.DiffRemoved {
			risk = fmt.Sprintf("-%s", risk)
		}

		key := k.Key
		if strings.HasPrefix(risk, "+") {
			key = fmt.Sprintf("**%s**", key)
		}
		data = append(data, []string{risk, key, desc})
	}

	table := tablewriter.NewWriter(w)
	table.SetAutoWrapText(false)
	table.SetHeader([]string{"Risk", "Key", "Description"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(data) // Add Bulk Data
	table.Render()
	fmt.Fprintln(w, "")
}
