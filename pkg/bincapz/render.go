package bincapz

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/olekukonko/tablewriter"
)

func RenderTable(res *Report, w io.Writer) {
	for path, fr := range res.Files {
		fmt.Printf("%s\n", path)
		keys := []string{}
		for key := range fr.Behaviors {
			keys = append(keys, key)
		}
		slices.Sort(keys)

		data := [][]string{}
		for _, k := range keys {
			b := fr.Behaviors[k]
			val := strings.Join(b.Strings, " ")
			if len(val) > 24 {
				val = val[0:24] + ".."
			}
			data = append(data, []string{fmt.Sprintf("%d", b.Risk), k, val, b.Description})
		}
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
