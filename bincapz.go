// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// bincapz returns information about a binaries capabilities
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/chainguard-dev/bincapz/pkg/action"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/compile"
	"github.com/chainguard-dev/bincapz/pkg/profile"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/rules"
	thirdparty "github.com/chainguard-dev/bincapz/third_party"
	"github.com/chainguard-dev/clog"
)

func main() {
	allFlag := flag.Bool("all", false, "Ignore nothing, show all")
	diffFlag := flag.Bool("diff", false, "Show capability drift between two files")
	formatFlag := flag.String("format", "terminal", "Output type -- valid values are: json, markdown, simple, terminal, yaml")
	ignoreSelfFlag := flag.Bool("ignore-self", true, "Ignore the bincapz binary")
	ignoreTagsFlag := flag.String("ignore-tags", "", "Rule tags to ignore")
	outputFlag := flag.String("o", "", "write output to this path instead of stdout")
	includeDataFilesFlag := flag.Bool("data-files", false, "Include files that are detected as non-program (binary or source) files")
	minFileLevelFlag := flag.Int("min-file-level", 0, "Only show results for files that meet this risk level (1=low, 2=medium, 3=high, 4=critical)")
	minLevelFlag := flag.Int("min-level", 1, "Minimum risk level to show results for (1=low, 2=medium, 3=high, 4=critical)")
	ociFlag := flag.Bool("oci", false, "Scan an OCI image")
	omitEmptyFlag := flag.Bool("omit-empty", false, "Omit files that contain no matches")
	profileFlag := flag.Bool("profile", false, "Generate profile and trace files")
	statsFlag := flag.Bool("stats", false, "Show statistics about the scan")
	thirdPartyFlag := flag.Bool("third-party", true, "Include third-party rules, which may have licensing restrictions")
	verboseFlag := flag.Bool("verbose", false, "Emit verbose logging messages to stderr")
	flag.Parse()
	args := flag.Args()

	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelError)
	logOpts := &slog.HandlerOptions{Level: logLevel}
	log := clog.New(slog.NewTextHandler(os.Stderr, logOpts))

	var stop func()
	if *profileFlag {
		var err error
		stop, err = profile.Profile()
		if err != nil {
			log.Fatal("profiling failed", slog.Any("error", err))
		}
	}

	if len(args) == 0 {
		fmt.Printf("usage: bincapz [flags] <directories>")
		os.Exit(1)
	}

	if *verboseFlag {
		logOpts.AddSource = true
		logLevel.Set(slog.LevelDebug)
	}

	ctx := clog.WithLogger(context.Background(), log)
	clog.FromContext(ctx).Info("bincapz starting")

	ignoreTags := strings.Split(*ignoreTagsFlag, ",")
	includeDataFiles := *includeDataFilesFlag
	minLevel := *minLevelFlag
	stats := *statsFlag
	if *allFlag {
		ignoreTags = []string{}
		minLevel = -1
		includeDataFiles = true
		*ignoreSelfFlag = false
	}

	outFile := os.Stdout
	var err error
	if *outputFlag != "" {
		outFile, err = os.OpenFile(*outputFlag, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			log.Fatal("open file", slog.Any("error", err), slog.String("path", *outputFlag))
		}
	}
	defer func() {
		outFile.Close()
	}()

	renderer, err := render.New(*formatFlag, outFile)
	if err != nil {
		log.Fatal("invalid format", slog.Any("error", err), slog.String("format", *formatFlag))
	}

	rfs := []fs.FS{rules.FS}
	if *thirdPartyFlag {
		rfs = append(rfs, thirdparty.FS)
	}

	yrs, err := compile.Recursive(ctx, rfs)
	if err != nil {
		log.Fatal("YARA rule compilation", slog.Any("error", err))
	}

	bc := action.Config{
		IgnoreSelf:       *ignoreSelfFlag,
		IgnoreTags:       ignoreTags,
		IncludeDataFiles: includeDataFiles,
		MinFileScore:     *minFileLevelFlag,
		MinResultScore:   minLevel,
		OCI:              *ociFlag,
		OmitEmpty:        *omitEmptyFlag,
		Renderer:         renderer,
		Rules:            yrs,
		ScanPaths:        args,
		Stats:            stats,
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

	err = renderer.Full(ctx, res)
	if err != nil {
		log.Fatal("render failed", slog.Any("error", err))
	}

	if *profileFlag {
		stop()
	}
}
