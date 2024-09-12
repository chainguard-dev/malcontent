// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// bincapz returns information about a binaries capabilities
package main

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/chainguard-dev/bincapz/pkg/action"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/compile"
	"github.com/chainguard-dev/bincapz/pkg/profile"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/pkg/version"
	"github.com/chainguard-dev/bincapz/rules"
	thirdparty "github.com/chainguard-dev/bincapz/third_party"
	"github.com/chainguard-dev/clog"
	"github.com/hillu/go-yara/v4"

	"github.com/urfave/cli/v2"
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

var (
	allFlag                   bool
	concurrencyFlag           int
	errFirstHitFlag           bool
	errFirstMissFlag          bool
	formatFlag                string
	ignoreSelfFlag            bool
	ignoreTagsFlag            string
	includeDataFilesFlag      bool
	minFileLevelFlag          int
	minFileRiskFlag           string
	minLevelFlag              int
	minRiskFlag               string
	ociFlag                   bool
	outputFlag                string
	profileFlag               bool
	quantityIncreasesRiskFlag bool
	statsFlag                 bool
	thirdPartyFlag            bool
	verboseFlag               bool
)

var riskMap = map[string]int{
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
	"crit":     4,
	"critical": 4,
}

func main() {
	returnCode := ExitOK
	defer func() { os.Exit(returnCode) }()

	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelError)
	logOpts := &slog.HandlerOptions{Level: logLevel, AddSource: true}
	log := clog.New(slog.NewTextHandler(os.Stderr, logOpts))

	// variables to share between stages
	var (
		bc       bincapz.Config
		ctx      context.Context
		err      error
		outFile  = os.Stdout
		renderer bincapz.Renderer
		res      *bincapz.Report
		stop     func()
		ver      string
		yrs      *yara.Rules
	)

	ver, err = version.Version()
	if err != nil {
		returnCode = ExitActionFailed
	}

	app := &cli.App{
		Name:      "bincapz",
		Version:   ver,
		Usage:     "Detect malicious program behaviors",
		UsageText: "bincapz <flags> [diff, scan] <path>",
		Compiled:  time.Now(),
		// Close the output file and stop profiling if appropriate
		After: func(_ *cli.Context) error {
			// Close our output file (or stdout) after commands have run
			defer func() {
				outFile.Close()
			}()

			// Stop profiling if command was executed with that flag
			if profileFlag {
				stop()
			}
			return nil
		},
		// Handle shared initialization (flag parsing, rule compilation, configuration)
		Before: func(c *cli.Context) error {
			ctx = clog.WithLogger(c.Context, log)
			clog.FromContext(ctx).Info("bincapz starting")

			if profileFlag {
				var err error
				stop, err = profile.Profile()
				if err != nil {
					log.Error("profiling failed", slog.Any("error", err))
					returnCode = ExitProfilerError
					return nil
				}
			}

			if verboseFlag {
				logOpts.AddSource = true
				logLevel.Set(slog.LevelDebug)
			}

			ignoreTags := strings.Split(ignoreTagsFlag, ",")
			includeDataFiles := includeDataFilesFlag

			minRisk := riskMap[minRiskFlag]
			// Backwards compatibility
			if minLevelFlag != -1 {
				minRisk = minLevelFlag
			}

			minFileRisk := riskMap[minFileRiskFlag]
			// Backwards compatibility
			if minFileLevelFlag != -1 {
				minFileRisk = minFileLevelFlag
			}

			if allFlag {
				ignoreSelfFlag = false
				ignoreTags = []string{}
				includeDataFiles = true
				minFileRisk = -1
				minRisk = -1
			}

			if outputFlag != "" {
				outFile, err = os.OpenFile(outputFlag, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
				if err != nil {
					log.Error("open file", slog.Any("error", err), slog.String("path", outputFlag))
					returnCode = ExitInputOutput
					return err
				}
			}

			renderer, err = render.New(formatFlag, outFile)
			if err != nil {
				log.Error("invalid format", slog.Any("error", err), slog.String("format", formatFlag))
				returnCode = ExitInvalidArgument
				return err
			}

			rfs := []fs.FS{rules.FS}
			if thirdPartyFlag {
				rfs = append(rfs, thirdparty.FS)
			}

			yrs, err = compile.Recursive(ctx, rfs)
			if err != nil {
				log.Error("YARA rule compilation", slog.Any("error", err))
				returnCode = ExitInvalidRules
				return err
			}

			// when scanning, increment the slice index by one to account for flags
			args := c.Args().Slice()
			scanPaths := args[1:]
			if slices.Contains(args, "analyze") || slices.Contains(args, "scan") {
				scanPaths = args[2:]
			}

			bc = bincapz.Config{
				Concurrency:           concurrencyFlag,
				ErrFirstHit:           errFirstHitFlag,
				ErrFirstMiss:          errFirstMissFlag,
				IgnoreSelf:            ignoreSelfFlag,
				IgnoreTags:            ignoreTags,
				IncludeDataFiles:      includeDataFiles,
				MinFileRisk:           minFileRisk,
				MinRisk:               minRisk,
				OCI:                   ociFlag,
				QuantityIncreasesRisk: quantityIncreasesRiskFlag,
				Renderer:              renderer,
				Rules:                 yrs,
				ScanPaths:             scanPaths,
				Stats:                 statsFlag,
			}

			return nil
		},
		// Global flags shared between commands
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "all",
				Value:       false,
				Usage:       "Ignore nothing within a provided scan path",
				Destination: &allFlag,
			},
			&cli.BoolFlag{
				Name:        "err-first-miss",
				Value:       false,
				Usage:       "Exit with error if scan source has no matching capabilities",
				Destination: &errFirstMissFlag,
			},
			&cli.BoolFlag{
				Name:        "err-first-hit",
				Value:       false,
				Usage:       "Exit with error if scan source has matching capabilities",
				Destination: &errFirstHitFlag,
			},
			&cli.StringFlag{
				Name:        "format",
				Value:       "terminal",
				Usage:       "Output format (json, markdown, simple, terminal, yaml)",
				Destination: &formatFlag,
			},
			&cli.BoolFlag{
				Name:        "ignore-self",
				Value:       true,
				Usage:       "Ignore the bincapz binary",
				Destination: &ignoreSelfFlag,
			},
			&cli.StringFlag{
				Name:        "ignore-tags",
				Value:       "",
				Usage:       "Rule tags to ignore",
				Destination: &ignoreTagsFlag,
			},
			&cli.BoolFlag{
				Name:        "include-data-files",
				Value:       false,
				Usage:       "Include files that are detected as non-program (binary or source) files",
				Destination: &includeDataFilesFlag,
			},
			&cli.IntFlag{
				Name:        "jobs",
				Aliases:     []string{"j"},
				Value:       runtime.NumCPU(),
				Usage:       "Concurrently scan files within target scan paths",
				Destination: &concurrencyFlag,
			},
			&cli.IntFlag{
				Name:        "min-file-level",
				Value:       -1,
				Usage:       "Obsoleted by --min-file-risk",
				Destination: &minFileLevelFlag,
			},
			&cli.StringFlag{
				Name:        "min-file-risk",
				Value:       "low",
				Usage:       "Only show results for files which meet the given risk level (any, low, medium, high, critical)",
				Destination: &minFileRiskFlag,
			},
			&cli.IntFlag{
				Name:        "min-level",
				Value:       -1,
				Usage:       "Obsoleted by --min-risk",
				Destination: &minLevelFlag,
			},
			&cli.StringFlag{
				Name:        "min-risk",
				Value:       "low",
				Usage:       "Only show results which meet the given risk level (any, low, medium, high, critical)",
				Destination: &minRiskFlag,
			},
			&cli.StringFlag{
				Name:        "output",
				Aliases:     []string{"o"},
				Value:       "",
				Usage:       "Write output to specified file instead of stdout",
				Destination: &outputFlag,
			},
			&cli.BoolFlag{
				Name:        "profile",
				Aliases:     []string{"p"},
				Value:       false,
				Usage:       "Generate profile and trace files",
				Destination: &profileFlag,
			},
			&cli.BoolFlag{
				Name:        "quantity-increases-risk",
				Value:       true,
				Usage:       "Increase file risk score based on behavior quantity",
				Destination: &quantityIncreasesRiskFlag,
			},
			&cli.BoolFlag{
				Name:        "stats",
				Aliases:     []string{"s"},
				Value:       false,
				Usage:       "Show scan statistics",
				Destination: &statsFlag,
			},
			&cli.BoolFlag{
				Name:        "third-party",
				Value:       true,
				Usage:       "Include third-party rules which may have licensing restrictions",
				Destination: &thirdPartyFlag,
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Value:       false,
				Usage:       "Emit verbose logging messages to stderr",
				Destination: &verboseFlag,
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "analyze",
				Usage: "fully interrogate a path",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "image",
						Aliases: []string{"i"},
						Value:   "",
						Usage:   "Scan an image",
					},
				},
				Action: func(c *cli.Context) error {
					// Handle edge cases
					// Set bc.OCI if the image flag is used
					// Default to path scanning if neither flag is passed (images must be scanned via --image or -i)
					switch {
					case c.String("image") != "":
						bc.OCI = true
					case c.String("image") == "":
						cmdArgs := c.Args().Slice()
						bc.ScanPaths = []string{cmdArgs[0]}
					}

					res, err = action.Scan(ctx, bc)
					if err != nil {
						log.Error("scan failed", slog.Any("error", err))
						returnCode = ExitActionFailed
						return err
					}

					err = renderer.Full(ctx, res)
					if err != nil {
						log.Error("render failed", slog.Any("error", err))
						returnCode = ExitRenderFailed
						return err
					}

					return nil
				},
			},
			{
				Name:  "diff",
				Usage: "scan and diff two paths",
				Action: func(_ *cli.Context) error {
					res, err = action.Diff(ctx, bc)
					if err != nil {
						log.Error("diff failed", slog.Any("error", err))
						returnCode = ExitActionFailed
						return err
					}

					err = renderer.Full(ctx, res)
					if err != nil {
						log.Error("render failed", slog.Any("error", err))
						returnCode = ExitRenderFailed
						return err
					}
					return nil
				},
			},
			{
				Name:  "scan",
				Usage: "tersely scan a path and return findings of the highest severity",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "image",
						Aliases: []string{"i"},
						Value:   "",
						Usage:   "Scan an image",
					},
				},
				Action: func(c *cli.Context) error {
					bc.Scan = true
					// Handle edge cases
					// Set bc.OCI if the image flag is used
					// Default to path scanning if neither flag is passed (images must be scanned via --image or -i)
					switch {
					case c.String("image") != "":
						bc.OCI = true
					case c.String("image") == "":
						cmdArgs := c.Args().Slice()
						bc.ScanPaths = []string{cmdArgs[0]}
					}

					res, err = action.Scan(ctx, bc)
					if err != nil {
						log.Error("scan failed", slog.Any("error", err))
						returnCode = ExitActionFailed
						return err
					}

					err = renderer.Full(ctx, res)
					if err != nil {
						log.Error("render failed", slog.Any("error", err))
						returnCode = ExitRenderFailed
						return err
					}

					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Error("error running bincapz: %w", slog.Any("error", err))
		returnCode = ExitActionFailed
	}
}
