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
	"github.com/chainguard-dev/bincapz/pkg/version"
	"github.com/chainguard-dev/bincapz/rules"
	thirdparty "github.com/chainguard-dev/bincapz/third_party"
	"github.com/chainguard-dev/clog"
)

var (
	// Exit codes based on diff(1) and https://man.freebsd.org/cgi/man.cgi?errno(2)
	ExitOK              = 0
	ExitActionFailed    = 2
	ExitProfilerError   = 3
	ExitInputOutput     = 5
	ExitRenderFailed    = 11
	ExitInvalidRules    = 14
	ExitInvalidArgument = 22
)

// parse risk levels.
func parseRisk(s string) int {
	levels := map[string]int{
		"0":        0,
		"any":      0,
		"all":      0,
		"1":        1,
		"low":      1,
		"2":        2,
		"medium":   2,
		"3":        3,
		"high":     3,
		"4":        4,
		"critical": 4,
	}
	return levels[strings.ToLower(s)]
}

func main() {
	allFlag := flag.Bool("all", false, "Ignore nothing, show all")
	diffFlag := flag.Bool("diff", false, "Show capability drift between two files")
	formatFlag := flag.String("format", "terminal", "Output type -- valid values are: json, markdown, simple, terminal, yaml")
	ignoreSelfFlag := flag.Bool("ignore-self", true, "Ignore the bincapz binary")
	ignoreTagsFlag := flag.String("ignore-tags", "", "Rule tags to ignore")
	outputFlag := flag.String("o", "", "write output to this path instead of stdout")
	includeDataFilesFlag := flag.Bool("data-files", false, "Include files that are detected as non-program (binary or source) files")
	minFileLevelFlag := flag.Int("min-file-level", -1, "Obsoleted by --min-file-risk")
	minLevelFlag := flag.Int("min-level", -1, "Obsoleted by --min-risk")
	minFileRiskFlag := flag.String("min-file-risk", "low", "Only show results for files that meet this risk level (any,low,medium,high,critical")
	minRiskFlag := flag.String("min-risk", "low", "Minimum risk level to show results for (any,low,medium,high,critical)")
	errFirstMissFlag := flag.Bool("err-first-miss", false, "exit with error if scan source has no matching capabilities")
	errFirstHitFlag := flag.Bool("err-first-hit", false, "exit with error if scan source has matching capabilities")
	ociFlag := flag.Bool("oci", false, "Scan an OCI image")
	omitEmptyFlag := flag.Bool("omit-empty", false, "Omit files that contain no matches")
	profileFlag := flag.Bool("profile", false, "Generate profile and trace files")
	statsFlag := flag.Bool("stats", false, "Show statistics about the scan")
	thirdPartyFlag := flag.Bool("third-party", true, "Include third-party rules, which may have licensing restrictions")
	verboseFlag := flag.Bool("verbose", false, "Emit verbose logging messages to stderr")
	versionFlag := flag.Bool("version", false, "Show version information")

	flag.Parse()
	args := flag.Args()

	returnCode := ExitOK
	defer func() { os.Exit(returnCode) }()

	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelError)
	logOpts := &slog.HandlerOptions{Level: logLevel, AddSource: true}
	log := clog.New(slog.NewTextHandler(os.Stderr, logOpts))

	var stop func()
	if *profileFlag {
		var err error
		stop, err = profile.Profile()
		if err != nil {
			log.Error("profiling failed", slog.Any("error", err))
			returnCode = ExitProfilerError
			return
		}
	}

	if len(args) == 0 && !*versionFlag {
		fmt.Printf("usage: bincapz [flags] <directories>")
		returnCode = ExitInvalidArgument
		return
	}

	if *verboseFlag {
		logOpts.AddSource = true
		logLevel.Set(slog.LevelDebug)
	}

	if *versionFlag {
		ver, err := version.Version()
		if err != nil {
			fmt.Printf("bincapz unknown version\n")
		}
		fmt.Printf("%s\n", ver)
		return
	}

	ctx := clog.WithLogger(context.Background(), log)
	clog.FromContext(ctx).Info("bincapz starting")

	ignoreTags := strings.Split(*ignoreTagsFlag, ",")
	includeDataFiles := *includeDataFilesFlag
	minRisk := parseRisk(*minRiskFlag)

	// Backwards compatibility
	if *minLevelFlag != -1 {
		minRisk = *minLevelFlag
	}

	minFileRisk := parseRisk(*minFileRiskFlag)

	// Backwards compatibility
	if *minFileLevelFlag != -1 {
		minFileRisk = *minFileLevelFlag
	}

	stats := *statsFlag
	if *allFlag {
		ignoreTags = []string{}
		minRisk = -1
		includeDataFiles = true
		*ignoreSelfFlag = false
	}

	outFile := os.Stdout
	var err error
	if *outputFlag != "" {
		outFile, err = os.OpenFile(*outputFlag, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			log.Error("open file", slog.Any("error", err), slog.String("path", *outputFlag))
			returnCode = ExitInputOutput
			return
		}
	}
	defer func() {
		outFile.Close()
	}()

	renderer, err := render.New(*formatFlag, outFile)
	if err != nil {
		log.Error("invalid format", slog.Any("error", err), slog.String("format", *formatFlag))
		returnCode = ExitInvalidArgument
		return
	}

	rfs := []fs.FS{rules.FS}
	if *thirdPartyFlag {
		rfs = append(rfs, thirdparty.FS)
	}

	yrs, err := compile.Recursive(ctx, rfs)
	if err != nil {
		log.Error("YARA rule compilation", slog.Any("error", err))
		returnCode = ExitInvalidRules
		return
	}

	bc := action.Config{
		IgnoreSelf:       *ignoreSelfFlag,
		IgnoreTags:       ignoreTags,
		IncludeDataFiles: includeDataFiles,
		MinFileRisk:      minFileRisk,
		MinRisk:          minRisk,
		OCI:              *ociFlag,
		OmitEmpty:        *omitEmptyFlag,
		Renderer:         renderer,
		Rules:            yrs,
		ScanPaths:        args,
		Stats:            stats,
		ErrFirstHit:      *errFirstHitFlag,
		ErrFirstMiss:     *errFirstMissFlag,
	}

	var res *bincapz.Report

	if *diffFlag {
		res, err = action.Diff(ctx, bc)
	} else {
		res, err = action.Scan(ctx, bc)
	}
	if err != nil {
		returnCode = ExitActionFailed
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	err = renderer.Full(ctx, res)
	if err != nil {
		returnCode = ExitRenderFailed
		log.Error("render failed", slog.Any("error", err))
		return
	}

	if *profileFlag {
		stop()
	}
}
