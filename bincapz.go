// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// bincapz returns information about a binaries capabilities
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/chainguard-dev/bincapz/pkg/action"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/pkg/rules"
	"github.com/chainguard-dev/clog"
)

func main() {
	formatFlag := flag.String("format", "terminal", "Output type. Valid values are: json, markdown, simple, terminal, yaml")
	ignoreTagsFlag := flag.String("ignore-tags", "", "Rule tags to ignore")
	minLevelFlag := flag.Int("min-level", 1, "minimum suspicion level to report (1=low, 2=medium, 3=high, 4=critical)")
	thirdPartyFlag := flag.Bool("third-party", true, "include third-party rules, which may have licensing restrictions")
	omitEmptyFlag := flag.Bool("omit-empty", false, "omit files that contain no matches")
	includeDataFilesFlag := flag.Bool("data-files", false, "include files that are detected to as non-program (binary or source) files")
	diffFlag := flag.Bool("diff", false, "show capability drift between two files")
	allFlag := flag.Bool("all", false, "Ignore nothing, show all")
	verboseFlag := flag.Bool("verbose", false, "emit verbose logging messages to stderr")

	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		fmt.Printf("usage: bincapz [flags] <directories>")
		os.Exit(1)
	}

	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelError)
	logOpts := &slog.HandlerOptions{Level: logLevel}

	if *verboseFlag {
		logOpts.AddSource = true
		logLevel.Set(slog.LevelDebug)
	}

	log := clog.New(slog.NewTextHandler(os.Stderr, logOpts))
	ctx := clog.WithLogger(context.Background(), log)
	clog.FromContext(ctx).Info("bincapz starting")

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
		log.Fatal("invalid format", slog.Any("error", err), slog.String("format", *formatFlag))
	}

	yrs, err := rules.Compile(ctx, rules.FS, *thirdPartyFlag)
	if err != nil {
		log.Fatal("YARA rule compilation", slog.Any("error", err))
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
		res, err = action.Diff(ctx, bc)
	} else {
		res, err = action.Scan(ctx, bc)
	}
	if err != nil {
		log.Fatal("failed", slog.Any("error", err))
	}

	err = renderer.Full(ctx, *res)
	if err != nil {
		clog.Fatal("render failed", slog.Any("error", err))
	}
}
