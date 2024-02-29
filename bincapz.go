// bincapz returns information about a binaries capabilities
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
)

//go:embed rules third_party
var ruleFs embed.FS

func main() {
	formatFlag := flag.String("format", "table", "Output type. Valid values are: table, simple, json, yaml")
	ignoreTagsFlag := flag.String("ignore-tags", "", "Rule tags to ignore")
	minLevelFlag := flag.Int("min-level", 1, "minimum suspicion level to report (1=low, 2=medium, 3=high, 4=critical)")
	thirdPartyFlag := flag.Bool("third-party", true, "include third-party rules, which may have licensing restrictions")
	allFlag := flag.Bool("all", false, "Ignore nothing, show all")

	klog.InitFlags(nil)
	flag.Set("logtostderr", "false")
	flag.Set("alsologtostderr", "false")
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		fmt.Printf("usage: bincap [flags] <directories>\n")
		os.Exit(2)
	}

	ignoreTags := strings.Split(*ignoreTagsFlag, ",")
	minLevel := *minLevelFlag
	if *allFlag {
		ignoreTags = []string{}
		minLevel = -1
	}

	bc := bincapz.Config{
		RuleFS:          ruleFs,
		ScanPaths:       args,
		IgnoreTags:      ignoreTags,
		MinLevel:        minLevel,
		ThirdPartyRules: *thirdPartyFlag,
	}

	res, err := bincapz.Scan(bc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(3)
	}

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
		bincapz.RenderSimple(res, os.Stdout)
	case "table":
		bincapz.RenderTable(res, os.Stdout)
	default:
		fmt.Printf("what kind of format is %q?\n", *formatFlag)
		os.Exit(3)
	}
	if err != nil {
		klog.Errorf("failed: %v", err)
		os.Exit(1)
	}
}
