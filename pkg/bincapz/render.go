package bincapz

import (
	"fmt"
	"io"
	"os"
	"slices"
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

type RenderFunc func(f *FileReport, w io.Writer)

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

func RenderTable(fr *FileReport, w io.Writer) {
	path := fr.Path
	if fr.Error != "" {
		fmt.Printf("%s - error: %s\n", path, fr.Error)
		return
	}

	if fr.Skipped != "" {
		fmt.Printf("%s - skipped: %s\n", path, fr.Skipped)
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
	riskWidth := 6
	padding := 4
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
			desc = fmt.Sprintf("%s:\n%s", desc, forceWrap(strings.Join(k.Behavior.Values, "\n"), descWidth))
		}

		key := forceWrap(k.Key, keyWidth)
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
		data = append(data, []string{fmt.Sprintf("%d/%s", k.Behavior.RiskScore, k.Behavior.RiskLevel), key, desc})
	}

	fmt.Fprintf(w, "%s\n%s\n", path, strings.Repeat("-", maxKeyLen+riskWidth+padding+64))

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	//	table.SetHeader([]string{"Risk", "Key", "Description"})
	table.SetBorder(false)
	//	ttable.SetBorders(tablewriter.Border{Left: false, Top: true, Right: false, Bottom: false})
	table.SetNoWhiteSpace(true)
	table.SetTablePadding("  ")

	for _, d := range data {
		if strings.Contains(d[0], "LOW") {
			table.Rich(d, []tablewriter.Colors{{tablewriter.Normal, tablewriter.FgGreenColor}})
			continue
		}

		if strings.Contains(d[0], "MED") {
			table.Rich(d, []tablewriter.Colors{{tablewriter.Normal, tablewriter.FgYellowColor}})
			continue
		}

		if strings.Contains(d[0], "HIGH") {
			table.Rich(d, []tablewriter.Colors{{tablewriter.Normal, tablewriter.FgRedColor}})
			continue
		}
		if strings.Contains(d[0], "CRIT") {
			table.Rich(d, []tablewriter.Colors{{tablewriter.Normal, tablewriter.FgHiRedColor}})
			continue
		}

		table.Append(d)
	}
	table.Render()

	fmt.Println("")
}

func RenderSimple(fr *FileReport, w io.Writer) {
	path := fr.Path
	fmt.Fprintf(w, "# %s\n", path)
	keys := []string{}
	for key := range fr.Behaviors {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		fmt.Fprintf(w, "- %s\n", key)
	}
}
