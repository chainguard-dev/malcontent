package bincapz

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
	"golang.org/x/term"
	"k8s.io/klog/v2"
)

type KeyedBehavior struct {
	Key      string
	Behavior Behavior
}

type RenderConfig struct {
	Title       string
	ShowTitle   bool
	DiffRemoved bool
	DiffAdded   bool
}

type RenderFunc func(f *FileReport, w io.Writer, rc RenderConfig)

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

func RenderTable(fr *FileReport, w io.Writer, rc RenderConfig) {
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
		return kbs[i].Behavior.RiskScore < kbs[j].Behavior.RiskScore
	})

	data := [][]string{}

	for k, v := range fr.Meta {
		data = append(data, []string{"meta", k, v})
	}
	if len(data) > 0 {
		data = append(data, []string{"", "", ""})
	}

	tWidth := terminalWidth()
	keyWidth := 36
	riskWidth := 7
	padding := 7
	descWidth := tWidth - keyWidth - riskWidth - padding
	if descWidth > 120 {
		descWidth = 120
	}

	klog.Infof("terminal width: %d - desc width: %d", tWidth, descWidth)
	maxKeyLen := 0

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

		key := forceWrap(k.Key, keyWidth)
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
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

		data = append(data, []string{risk, key, desc})
	}

	if title != "" {
		fmt.Fprintf(w, "%s\n%s\n", title, strings.Repeat("-", maxKeyLen+riskWidth+padding+64))
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	//	table.SetHeader([]string{"Risk", "Key", "Description"})
	table.SetBorder(false)
	//	ttable.SetBorders(tablewriter.Border{Left: false, Top: true, Right: false, Bottom: false})
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

func RenderDiff(r *Report, w io.Writer) {
	for f, fr := range r.Diff.Removed {
		RenderTable(&fr, w, RenderConfig{Title: fmt.Sprintf("➖ file removed: %s", f), DiffRemoved: true})
	}

	for f, fr := range r.Diff.Added {
		RenderTable(&fr, w, RenderConfig{Title: fmt.Sprintf("➕ file added: %s", f), DiffAdded: true})
	}

	for _, fr := range r.Diff.Modified {
		RenderTable(&fr, w, RenderConfig{Title: fmt.Sprintf("🐙 changed behaviors: %s", fr.Path)})
	}
}
