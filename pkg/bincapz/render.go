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

	fmt.Printf("%s\n", path)

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
		data = append(data, []string{"-", k, v, ""})
	}
	if len(data) > 0 {
		data = append(data, []string{"", "", "", ""})
	}

	valWidth := 24
	width := terminalWidth()
	if width > 110 {
		valWidth += (width - 110)
	}
	if valWidth > 65 {
		valWidth = 65
	}

	klog.Infof("terminal width: %d / val width: %d", width, valWidth)

	for _, k := range kbs {
		val := strings.Join(k.Behavior.Strings, "|||")
		val = forceWrap(val, valWidth)
		val = strings.ReplaceAll(val, "|||", "\n")

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

		words, _ := tablewriter.WrapString(desc, 52)
		desc = strings.Join(words, "\n")

		data = append(data, []string{fmt.Sprintf("%d/%s", k.Behavior.RiskScore, k.Behavior.RiskLevel), k.Key, val, desc})
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	table.SetHeader([]string{"Risk", "Key", "Values", "Description"})
	//table.SetBorder(false)
	for _, d := range data {
		if strings.Contains(d[0], "LOW") {
			table.Rich(d, []tablewriter.Colors{tablewriter.Colors{tablewriter.Normal, tablewriter.FgGreenColor}})
			continue
		}

		if strings.Contains(d[0], "MED") {
			table.Rich(d, []tablewriter.Colors{tablewriter.Colors{tablewriter.Normal, tablewriter.FgYellowColor}})
			continue
		}

		if strings.Contains(d[0], "HIGH") {
			table.Rich(d, []tablewriter.Colors{tablewriter.Colors{tablewriter.Normal, tablewriter.FgRedColor}})
			continue
		}
		if strings.Contains(d[0], "CRIT") {
			table.Rich(d, []tablewriter.Colors{tablewriter.Colors{tablewriter.Normal, tablewriter.FgHiRedColor}})
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
