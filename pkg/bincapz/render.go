package bincapz

import (
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
)

type KeyedBehavior struct {
	Key      string
	Behavior Behavior
}

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

func RenderTable(res *Report, w io.Writer) {
	files := 0
	tableShown := false

	for path, fr := range res.Files {
		if files > 0 && tableShown {
			fmt.Print("\n")
		}
		fmt.Printf("%s\n", path)
		files++
		tableShown = false

		kbs := []KeyedBehavior{}
		for k, b := range fr.Behaviors {
			kbs = append(kbs, KeyedBehavior{Key: k, Behavior: b})
		}

		if len(kbs) == 0 {
			continue
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

		for _, k := range kbs {
			val := strings.Join(k.Behavior.Strings, " ")
			val = forceWrap(val, 32)

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

			words, _ := tablewriter.WrapString(desc, 48)
			desc = strings.Join(words, "\n")

			data = append(data, []string{fmt.Sprintf("%d/%s", k.Behavior.RiskScore, k.Behavior.RiskLevel), k.Key, val, desc})
		}
		tableShown = true
		table := tablewriter.NewWriter(os.Stdout)
		table.SetAutoWrapText(false)
		table.SetHeader([]string{"Risk", "Key", "Values", "Description"})
		//table.SetBorder(false)
		table.AppendBulk(data) // Add Bulk Data
		table.Render()

		if fr.FilteredBehaviors > 0 {
			fmt.Fprintf(w, "\n# %d behavior(s) filtered out, use --all to see more\n", fr.FilteredBehaviors)
		}
	}
}

func RenderSimple(res *Report, w io.Writer) {
	for path, fr := range res.Files {
		fmt.Fprintf(w, "# %s\n", path)
		keys := []string{}
		for key := range fr.Behaviors {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			fmt.Fprintf(w, "- %s\n", key)
		}

		if fr.FilteredBehaviors > 0 {
			fmt.Fprintf(w, "\n# %d behavior(s) filtered out, use --all to see more\n", fr.FilteredBehaviors)
		}
	}
}
