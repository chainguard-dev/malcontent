package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tstromberg/bincapz/pkg/bincapz"
	"k8s.io/klog/v2"
)

func main() {
	rulesDirFlag := flag.String("rules-dir", "rules", "Path to rules file")
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		fmt.Printf("usage: bincap [flags] <directories>\n")
		os.Exit(2)
	}

	bc := bincapz.Config{
		RulePaths: []string{*rulesDirFlag},
		ScanPaths: args,
	}

	res, err := bincapz.Scan(bc)

	for _, fr := range res.Files {
		fmt.Printf("%s\n", fr.Path)
		for _, c := range fr.Capabilities {
			fmt.Printf("- %s: %s\n", c.Key, strings.Join(c.Markers, ", "))
		}
	}
	// klog.Infof("res: %+v", res)
	if err != nil {
		klog.Errorf("failed: %v", err)
		os.Exit(1)
	}
}
