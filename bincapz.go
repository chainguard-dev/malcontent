// bincapz returns information about a binaries capabilities
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tstromberg/bincapz/pkg/bincapz"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
)

//go:embed rules
var ruleFs embed.FS

func main() {
	jsonFlag := flag.Bool("json", false, "JSON output")
	yamlFlag := flag.Bool("yaml", false, "YAML output")
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

	for path, fr := range res.Files {
		fmt.Printf("%s\n", path)
		for key := range fr.Behaviors {
			fmt.Printf("- %s\n", key)
		}
	}
	// klog.Infof("res: %+v", res)
	if err != nil {
		klog.Errorf("failed: %v", err)
		os.Exit(1)
	}
}
