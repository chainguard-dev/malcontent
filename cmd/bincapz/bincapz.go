package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/tstromberg/bincapz/pkg/bincapz"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
)

func main() {
	rulesDirFlag := flag.String("rules-dir", "rules", "Path to rules file")
	jsonFlag := flag.Bool("json", false, "JSON output")
	yamlFlag := flag.Bool("yaml", false, "YAML output")
	ignoreTagsFlag := flag.String("ignore-tags", "harmless", "Rule tags to ignore")
	outputFlag := flag.String("output", "caps", "output type: caps,pledges,syscalls")
	allFlag := flag.Bool("all", false, "Ignore nothing, show all")

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
		RulePaths:  []string{*rulesDirFlag},
		ScanPaths:  args,
		IgnoreTags: ignoreTags,
	}

	res, err := bincapz.Scan(bc)

	if *jsonFlag {
		json, err := json.Marshal(res)
		if err != nil {
			klog.Fatalf("marshal: %v", err)
		}
		fmt.Printf("%s\n", json)
		os.Exit(0)
	}

	if *yamlFlag {
		yaml, err := yaml.Marshal(res)
		if err != nil {
			klog.Fatalf("marshal: %v", err)
		}
		fmt.Printf("%s\n", yaml)
		os.Exit(0)
	}

	for _, fr := range res.Files {
		fmt.Printf("%s\n", fr.Path)
		deets := []string{}
		for _, c := range fr.Capabilities {
			key := c.Key
			switch *outputFlag {
			case "pledges":
				key = c.Pledge
			case "syscalls":
				key = c.Syscall
			}
			if key != "" {
				deets = append(deets, key)
			}
		}

		slices.Sort(deets)
		for _, d := range slices.Compact(deets) {
			fmt.Printf("- %s\n", d)
		}
	}
	// klog.Infof("res: %+v", res)
	if err != nil {
		klog.Errorf("failed: %v", err)
		os.Exit(1)
	}
}
