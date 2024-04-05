// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// bincapz returns information about a binaries capabilities
package main

import (
	"embed"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/chainguard-dev/bincapz/pkg/action"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/pkg/rules"
	"k8s.io/klog/v2"
)

//go:embed rules third_party
var ruleFs embed.FS

func main() {
	formatFlag := flag.String("format", "terminal", "Output type. Valid values are: json, markdown, simple, terminal, yaml")
	ignoreTagsFlag := flag.String("ignore-tags", "", "Rule tags to ignore")
	minLevelFlag := flag.Int("min-level", 1, "minimum suspicion level to report (1=low, 2=medium, 3=high, 4=critical)")
	thirdPartyFlag := flag.Bool("third-party", true, "include third-party rules, which may have licensing restrictions")
	omitEmptyFlag := flag.Bool("omit-empty", false, "omit files that contain no matches")
	includeDataFilesFlag := flag.Bool("data-files", false, "include files that are detected to as non-program (binary or source) files")
	diffFlag := flag.Bool("diff", false, "show capability drift between two files")
	allFlag := flag.Bool("all", false, "Ignore nothing, show all")

	klog.InitFlags(nil)
	flag.Set("logtostderr", "false")
	flag.Set("alsologtostderr", "false")
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		fmt.Printf("usage: bincapz [flags] <directories>\n")
		os.Exit(2)
	}

	ignoreTags := strings.Split(*ignoreTagsFlag, ",")
	includeDataFiles := *includeDataFilesFlag
	minLevel := *minLevelFlag
	if *allFlag {
		ignoreTags = []string{}
		minLevel = -1
		includeDataFiles = true
	}

	renderer, err := render.New(*formatFlag, os.Stdout)
	if err != nil {
		fmt.Printf("what kind of format is %q?\n", *formatFlag)
		os.Exit(3)
	}

	yrs, err := rules.Compile(ruleFs, *thirdPartyFlag)
	if err != nil {
		fmt.Printf("YARA rule compilation: %v", err)
		os.Exit(4)
	}

	bc := action.Config{
		Rules:            yrs,
		ScanPaths:        args,
		IgnoreTags:       ignoreTags,
		OmitEmpty:        *omitEmptyFlag,
		MinLevel:         minLevel,
		IncludeDataFiles: includeDataFiles,
		Renderer:         renderer,
	}

	var res *bincapz.Report

	if *diffFlag {
		res, err = action.Diff(bc)
	} else {
		res, err = action.Scan(bc)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "failed: %v\n", err)
		os.Exit(3)
	}

	renderer.Full(*res)

	if err != nil {
		klog.Errorf("failed: %v", err)
		os.Exit(1)
	}
}
