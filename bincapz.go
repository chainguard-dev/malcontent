// bincapz returns information about a binaries capabilities
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/tstromberg/bincapz/pkg/bincapz"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
)

//go:embed rules
var ruleFs embed.FS

func main() {
	formatFlag := flag.String("format", "table", "Output type. Valid values are: table, simple, json, yaml")
	ignoreTagsFlag := flag.String("ignore-tags", "harmless", "Rule tags to ignore")
	// outputFlag := flag.String("output", "caps", "output type: caps,pledges,syscalls")
	allFlag := flag.Bool("all", false, "Ignore nothing, show all")

	klog.InitFlags(nil)

	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		fmt.Printf("usage: bincap [flags] <directories>\n")
		os.Exit(2)
	}

	ignoreTags := strings.Split(*ignoreTagsFlag, ",")
	if *allFlag {
		ignoreTags = []string{}
	}

	bc := bincapz.Config{
		RuleFS:     ruleFs,
		ScanPaths:  args,
		IgnoreTags: ignoreTags,
	}

	res, err := bincapz.Scan(bc)

	switch *formatFlag {
	case "json":
		json, err := json.MarshalIndent(res, "", "    ")
		if err != nil {
			klog.Fatalf("marshal: %v", err)
		}
		fmt.Printf("%s\n", json)
	case "yaml":
		yaml, err := yaml.Marshal(res)
		if err != nil {
			klog.Fatalf("marshal: %v", err)
		}
		fmt.Printf("%s\n", yaml)
	case "simple":
		filtered := 0

		for path, fr := range res.Files {
			fmt.Printf("# %s\n", path)
			keys := []string{}
			for key := range fr.Behaviors {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			for _, key := range keys {
				fmt.Printf("- %s\n", key)
			}
			if fr.FilteredBehaviors > 0 {
				filtered += fr.FilteredBehaviors
			}
		}

		if filtered > 0 {
			fmt.Printf("\n# %d behavior(s) filtered out, use --all to see more\n", filtered)
		}
	case "table":
		filtered := 0
		for path, fr := range res.Files {
			fmt.Printf("%s\n", path)
			keys := []string{}
			for key := range fr.Behaviors {
				keys = append(keys, key)
			}
			slices.Sort(keys)

			if fr.FilteredBehaviors > 0 {
				filtered += fr.FilteredBehaviors
			}

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

		}

		if filtered > 0 {
			fmt.Printf("\n%d behavior(s) filtered out, use --all to see them\n", filtered)
		}

	}
	if err != nil {
		klog.Errorf("failed: %v", err)
		os.Exit(1)
	}
}
