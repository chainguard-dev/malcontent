// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// malcontent returns information about a file's capabilities.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/release"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/action"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/profile"
	"github.com/chainguard-dev/malcontent/pkg/refresh"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"

	"github.com/urfave/cli/v3"
)

// Exit codes based on diff(1) and https://man.freebsd.org/cgi/man.cgi?errno(2)
var (
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
	diffImageFlag             bool
	diffReportFlag            bool
	exitExtractionFlag        bool
	exitExtractorPanicFlag    bool
	exitFirstHitFlag          bool
	exitFirstMissFlag         bool
	fileRiskChangeFlag        bool
	fileRiskIncreaseFlag      bool
	formatFlag                string
	ignoreRulesFlag           string
	ignoreSelfFlag            bool
	ignoreTagsFlag            string
	includeDataFilesFlag      bool
	maxArchiveBytesFlag       int64
	maxArchiveRatioFlag       float64
	maxDepthFlag              int
	maxImageSizeFlag          int64
	maxScanFilesFlag          int
	minFileLevelFlag          int
	minFileRiskFlag           string
	minLevelFlag              int
	minRiskFlag               string
	ociAuthFlag               bool
	ociFlag                   bool
	ociKeepalivePolicyFlag    string
	ociKeepaliveSecondsFlag   int
	ociPerHostSlotsFlag       int
	ociProxyOptInFlag         bool
	ociPullTimeoutFlag        int
	ociRetryMaxAttemptsFlag   int
	ociRetryMaxWindowFlag     int
	caBundleFlag              string
	outputFlag                string
	profileFlag               bool
	quantityIncreasesRiskFlag bool
	ruleCategoriesFlag        []string
	sensitivityFlag           int
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

// BuildVersion is the release version stamped at link time with
// -ldflags "-X main.BuildVersion=<version>". When it is empty, the version
// compiled into pkg/release is reported.
var BuildVersion string

// drainTimeout bounds how long in-flight work may drain after SIGINT or
// SIGTERM before the process is forced to exit.
const drainTimeout = 10 * time.Second

func showError(err error) {
	emoji := "💣"
	if errors.Is(err, action.ErrMatchedCondition) {
		emoji = "👋"
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", emoji, err.Error())
}

// cliState holds what the CLI's Before, Action, and After stages share.
type cliState struct {
	log        *clog.Logger
	logLevel   *slog.LevelVar
	mc         malcontent.Config
	outFile    *os.File
	profiler   *profile.Profiler
	renderer   malcontent.Renderer
	returnCode int
}

func main() {
	returnCode := ExitOK
	defer func() { os.Exit(returnCode) }()

	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelError)
	logOpts := &slog.HandlerOptions{Level: logLevel, AddSource: true}
	log := clog.New(slog.NewTextHandler(os.Stderr, logOpts))

	ctx, cancel := context.WithCancel(context.Background())
	ctx = clog.WithLogger(ctx, log)
	defer cancel()

	go handleContext(cancel, log)

	st := &cliState{log: log, logLevel: logLevel, outFile: os.Stdout}
	err := newApp(st).Run(ctx, os.Args)
	returnCode = exitCode(st.returnCode, err)
	if err != nil {
		showError(err)
	}
}

// exitCode maps the outcome of a CLI run to the process exit status. A
// failure keeps the specific code its stage recorded and falls back to
// ExitActionFailed when none was recorded; meeting an --exit-first-hit or
// --exit-first-miss condition is not a failure.
func exitCode(code int, err error) int {
	switch {
	case err == nil:
		return code
	case errors.Is(err, action.ErrMatchedCondition):
		return ExitOK
	case code == ExitOK:
		return ExitActionFailed
	default:
		return code
	}
}

// newApp builds the malcontent command tree; its stages share st.
func newApp(st *cliState) *cli.Command {
	return &cli.Command{
		Name:                  "malcontent",
		Version:               release.Version(BuildVersion),
		Usage:                 "Detect malicious program behaviors",
		UsageText:             "mal [GLOBAL FLAGS] <command> [COMMAND FLAGS] <path>",
		EnableShellCompletion: true,
		// Close the output file and stop profiling if appropriate
		After: st.after,
		// Handle shared initialization (flag parsing, rule compilation, configuration)
		Before: st.before,
		// Global flags shared between commands
		Flags: globalFlags(),
		Commands: []*cli.Command{
			{
				Name:   "analyze",
				Usage:  "fully interrogate a path",
				Flags:  targetFlags(),
				Action: st.analyze,
			},
			diffCommand(st),
			{
				Name:   "refresh",
				Usage:  "Refresh test data",
				Action: st.refreshTestData,
			},
			{
				Name:   "scan",
				Usage:  "tersely scan a path and return findings of the highest severity",
				Flags:  targetFlags(),
				Action: st.scan,
			},
		},
	}
}

// globalFlags returns the flags shared between commands.
func globalFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "all",
			Value:       false,
			Usage:       "Ignore nothing within a provided scan path",
			Destination: &allFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "exit-extraction",
			Value:       false,
			Usage:       "Exit when encountering file extraction errors",
			Destination: &exitExtractionFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "exit-on-extractor-panic",
			Value:       false,
			Usage:       "Terminate the process when an archive extractor panics instead of logging and continuing",
			Destination: &exitExtractorPanicFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "exit-first-miss",
			Value:       false,
			Usage:       "Exit with error if scan source has no matching capabilities",
			Destination: &exitFirstMissFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "exit-first-hit",
			Value:       false,
			Usage:       "Exit with error if scan source has matching capabilities",
			Destination: &exitFirstHitFlag,
			Local:       false,
		},
		&cli.StringFlag{
			Name:        "format",
			Value:       "auto",
			Usage:       "Output format (interactive, json, markdown, simple, strings, terminal, yaml)",
			Destination: &formatFlag,
			Local:       false,
		},
		&cli.StringFlag{
			Name:        "ignore-rules",
			Value:       "",
			Usage:       "YARA rule names to ignore (comma-separated; supports filepath.Match globs, e.g. 'py_lib_alias_val,py_lib_*'). Ignored rules are removed from the report before overall risk is computed.",
			Destination: &ignoreRulesFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "ignore-self",
			Value:       true,
			Usage:       "Ignore the malcontent binary",
			Destination: &ignoreSelfFlag,
			Local:       false,
		},
		&cli.StringFlag{
			Name:        "ignore-tags",
			Value:       "false_positive,ignore",
			Usage:       "Rule tags to ignore",
			Destination: &ignoreTagsFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "include-data-files",
			Value:       false,
			Usage:       "Include files that are detected as non-program (binary or source) files",
			Destination: &includeDataFilesFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "jobs",
			Aliases:     []string{"j"},
			Value:       runtime.NumCPU(),
			Usage:       "Concurrently scan files within target scan paths (effectively capped at GOMAXPROCS; higher values do not increase throughput)",
			Destination: &concurrencyFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "max-depth",
			Value:       32,
			Usage:       "Maximum depth for archive extraction (0 or -1 for unlimited)",
			Destination: &maxDepthFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "max-files",
			Value:       1 << 21, // ~2 million files
			Usage:       "Maximum number of files to scan (0 or -1 for unlimited)",
			Destination: &maxScanFilesFlag,
			Local:       false,
		},
		&cli.Int64Flag{
			Name:        "max-image-size",
			Value:       1 << 34, // ~16 GB
			Usage:       "Maximum OCI image size in bytes (0 or -1 for unlimited)",
			Destination: &maxImageSizeFlag,
			Local:       false,
		},
		&cli.Int64Flag{
			Name:        "max-archive-bytes",
			Value:       file.DefaultMaxArchiveBytes,
			Usage:       "Maximum total uncompressed bytes produced by archive extraction (0 for the built-in default)",
			Destination: &maxArchiveBytesFlag,
			Local:       false,
		},
		&cli.FloatFlag{
			Name:        "max-archive-ratio",
			Value:       file.DefaultMaxArchiveRatio,
			Usage:       "Maximum uncompressed:compressed expansion ratio for archive extraction (0 or less for the built-in default)",
			Destination: &maxArchiveRatioFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "min-file-level",
			Value:       -1,
			Usage:       "Obsoleted by --min-file-risk",
			Destination: &minFileLevelFlag,
			Local:       false,
		},
		&cli.StringFlag{
			Name:        "min-file-risk",
			Value:       "low",
			Usage:       "Only show results for files which meet the given risk level (any, low, medium, high, critical)",
			Destination: &minFileRiskFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "min-level",
			Value:       -1,
			Usage:       "Obsoleted by --min-risk",
			Destination: &minLevelFlag,
			Local:       false,
		},
		&cli.StringFlag{
			Name:        "min-risk",
			Value:       "low",
			Usage:       "Only show results which meet the given risk level (any, low, medium, high, critical)",
			Destination: &minRiskFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "oci-auth",
			Value:       false,
			Usage:       "Authenticate OCI pulls with MALCONTENT_REGISTRY_USER/PASS, scoped to the registry in MALCONTENT_REGISTRY_HOST",
			Destination: &ociAuthFlag,
			Local:       false,
		},
		&cli.StringFlag{
			Name:        "ca-bundle",
			Value:       "system",
			Usage:       "OCI registry CA bundle: system (default; use OS trust store) or absolute path to a PEM bundle",
			Destination: &caBundleFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "oci-pull-timeout-seconds",
			Value:       600, // OCI registry response-header timeout in seconds
			Usage:       "OCI registry response-header timeout in seconds (<=0 uses the built-in default)",
			Destination: &ociPullTimeoutFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "oci-retry-max-attempts",
			Value:       3, // OCI pull retry attempt ceiling
			Usage:       "Maximum OCI registry pull retry attempts (<=0 uses the built-in default)",
			Destination: &ociRetryMaxAttemptsFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "oci-retry-max-window-seconds",
			Value:       60, // OCI pull retry backoff window in seconds
			Usage:       "Maximum OCI registry pull retry backoff window in seconds (<=0 uses the built-in default)",
			Destination: &ociRetryMaxWindowFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "oci-per-host-slots",
			Value:       4, // concurrent OCI pull slots per registry host
			Usage:       "Maximum concurrent OCI pulls per registry host (<=0 uses the built-in default)",
			Destination: &ociPerHostSlotsFlag,
			Local:       false,
		},
		&cli.StringFlag{
			Name:        "oci-keepalive-policy",
			Value:       string(malcontent.KeepalivePolicyExplicitlyEnabled),
			Usage:       "OCI transport keepalive policy (enabled, disabled, go-default)",
			Destination: &ociKeepalivePolicyFlag,
			Local:       false,
		},
		&cli.IntFlag{
			Name:        "oci-keepalive-seconds",
			Value:       30, // OCI transport idle-connection timeout in seconds
			Usage:       "OCI transport idle-connection timeout in seconds when keepalive policy is enabled",
			Destination: &ociKeepaliveSecondsFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "oci-proxy-opt-in",
			Value:       false,
			Usage:       "Honor HTTP(S)_PROXY environment variables for OCI registry traffic",
			Destination: &ociProxyOptInFlag,
			Local:       false,
		},
		&cli.StringFlag{
			Name:        "output",
			Aliases:     []string{"o"},
			Value:       "",
			Usage:       "Write output to specified file instead of stdout",
			Destination: &outputFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "profile",
			Aliases:     []string{"p"},
			Value:       false,
			Usage:       "Generate profile and trace files",
			Destination: &profileFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "quantity-increases-risk",
			Value:       true,
			Usage:       "Increase file risk score based on behavior quantity",
			Destination: &quantityIncreasesRiskFlag,
			Local:       false,
		},
		&cli.StringSliceFlag{
			Name:        "rule-category",
			Value:       []string{},
			Usage:       "Only show matches whose rule path starts with one of the given categories (e.g. exfil, exfil/stealer); repeatable, no-op when unset",
			Destination: &ruleCategoriesFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "stats",
			Aliases:     []string{"s"},
			Value:       false,
			Usage:       "Show scan statistics",
			Destination: &statsFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "third-party",
			Value:       true,
			Usage:       "Include third-party rules which may have licensing restrictions",
			Destination: &thirdPartyFlag,
			Local:       false,
		},
		&cli.BoolFlag{
			Name:        "verbose",
			Value:       false,
			Usage:       "Emit verbose logging messages to stderr",
			Destination: &verboseFlag,
			Local:       false,
		},
	}
}

// targetFlags returns the scan target flags of the analyze and scan commands.
func targetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "image",
			Aliases: []string{"i"},
			Value:   []string{},
			Usage:   "Scan one or more images",
			Local:   true,
		},
		&cli.BoolFlag{
			Name:  "processes",
			Value: false,
			Usage: "Scan the commands (paths) of running processes",
			Local: true,
		},
	}
}

// diffCommand returns the diff command, which scans and compares two paths.
func diffCommand(st *cliState) *cli.Command {
	return &cli.Command{
		Name:  "diff",
		Usage: "scan and diff two paths",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "file-risk-change",
				Value:       false,
				Usage:       "Only show diffs when file risk changes",
				Destination: &fileRiskChangeFlag,
				Local:       true,
			},
			&cli.BoolFlag{
				Name:        "file-risk-increase",
				Value:       false,
				Usage:       "Only show diffs when file risk increases",
				Destination: &fileRiskIncreaseFlag,
				Local:       true,
			},
			&cli.BoolFlag{
				Name:        "image",
				Aliases:     []string{"i"},
				Value:       false,
				Usage:       "Scan an image",
				Destination: &diffImageFlag,
				Local:       true,
			},
			&cli.BoolFlag{
				Name:        "report",
				Aliases:     []string{"r"},
				Value:       false,
				Usage:       "Diff existing analyze/scan reports",
				Destination: &diffReportFlag,
				Local:       true,
			},
			&cli.IntFlag{
				Name:        "sensitivity",
				Aliases:     []string{"sens"},
				Value:       5,
				Usage:       "Control the sensitivity when diffing two files, paths, etc.",
				Destination: &sensitivityFlag,
				Local:       true,
			},
		},
		Action: st.diff,
	}
}

// after closes the output file (or stdout) and stops profiling once the
// selected command has run.
func (st *cliState) after(_ context.Context, _ *cli.Command) error {
	defer func() {
		if st.outFile != nil {
			_ = st.outFile.Close()
		}
	}()

	if st.profiler != nil {
		st.profiler.Stop()
	}
	return nil
}

// before handles the initialization shared between commands: it validates the
// global flags and prepares the configuration, renderer, and rules.
func (st *cliState) before(ctx context.Context, c *cli.Command) (context.Context, error) {
	clog.InfoContext(ctx, "malcontent starting")

	if profileFlag {
		p, err := profile.StartProfiling(ctx, profile.DefaultConfig())
		if err != nil {
			st.log.Error("profiling failed", slog.Any("error", err))
			st.returnCode = ExitProfilerError
			return ctx, fmt.Errorf("start profiling: %w", err)
		}
		st.profiler = p
	}

	if verboseFlag {
		st.logLevel.Set(slog.LevelDebug)
	}

	mc, err := configFromFlags()
	if err != nil {
		st.log.Errorf("%v", err)
		st.returnCode = ExitInvalidArgument
		return ctx, err
	}

	if outputFlag != "" {
		f, err := os.OpenFile(outputFlag, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- CLI flag values are user-supplied paths intended for the operation
		if err != nil {
			st.returnCode = ExitInputOutput
			return ctx, err
		}
		st.outFile = f
	}

	renderer, err := render.New(resolveFormat(formatFlag, c.Args().Slice()), st.outFile)
	if err != nil {
		st.returnCode = ExitInvalidArgument
		return ctx, err
	}
	st.renderer = renderer

	yrs, err := action.CachedRules(ctx, ruleFS(thirdPartyFlag))
	if err != nil {
		st.returnCode = ExitInvalidRules
		return ctx, fmt.Errorf("compile rules: %w", err)
	}

	mc.Renderer = renderer
	mc.Rules = yrs
	st.mc = mc
	return malcontent.ContextWithConfig(ctx, &st.mc), nil
}

// configFromFlags validates the parsed global flags and assembles the scan
// configuration they describe. The caller supplies the renderer and rules.
func configFromFlags() (malcontent.Config, error) {
	ignoreTags := strings.Split(ignoreTagsFlag, ",")
	ignoreRules := splitAndTrimCSV(ignoreRulesFlag)
	if err := report.ValidateIgnoreRules(ignoreRules); err != nil {
		return malcontent.Config{}, err
	}
	ignoreSelf := ignoreSelfFlag
	includeDataFiles := includeDataFilesFlag

	minRisk, exists := riskMap[minRiskFlag]
	if !exists {
		return malcontent.Config{}, fmt.Errorf("unknown risk: %q", minRiskFlag)
	}

	// Backwards compatibility
	if minLevelFlag != -1 {
		minRisk = minLevelFlag
	}

	minFileRisk, exists := riskMap[minFileRiskFlag]
	if !exists {
		return malcontent.Config{}, fmt.Errorf("unknown risk: %q", minFileRiskFlag)
	}

	// Backwards compatibility
	if minFileLevelFlag != -1 {
		minFileRisk = minFileLevelFlag
	}

	// Add the default tags to ignore regardless of whether they're passed in or not
	for _, t := range []string{"false_positive", "ignore"} {
		if !slices.Contains(ignoreTags, t) {
			ignoreTags = append(ignoreTags, t)
		}
	}

	if allFlag {
		ignoreRules = nil
		ignoreSelf = false
		ignoreTags = []string{}
		includeDataFiles = true
		minFileRisk = -1
		minRisk = -1
	}

	mc := malcontent.Config{
		Concurrency:              max(1, concurrencyFlag),
		ExitExtraction:           exitExtractionFlag,
		ExitOnExtractorPanic:     exitExtractorPanicFlag,
		ExitFirstHit:             exitFirstHitFlag,
		ExitFirstMiss:            exitFirstMissFlag,
		IgnoreRules:              ignoreRules,
		IgnoreSelf:               ignoreSelf,
		IgnoreTags:               ignoreTags,
		IncludeDataFiles:         includeDataFiles,
		MaxArchiveBytes:          maxArchiveBytesFlag,
		MaxArchiveRatio:          maxArchiveRatioFlag,
		MaxDepth:                 maxDepthFlag,
		MaxImageSize:             maxImageSizeFlag,
		MaxScanFiles:             maxScanFilesFlag,
		MinFileRisk:              minFileRisk,
		MinRisk:                  minRisk,
		OCIAuth:                  ociAuthFlag,
		OCI:                      ociFlag,
		OCICABundlePath:          caBundleFlag,
		OCIKeepalivePolicy:       malcontent.KeepalivePolicy(ociKeepalivePolicyFlag),
		OCIKeepaliveSeconds:      ociKeepaliveSecondsFlag,
		OCIPerHostSlots:          ociPerHostSlotsFlag,
		OCIProxyOptIn:            ociProxyOptInFlag,
		OCIPullTimeoutSeconds:    ociPullTimeoutFlag,
		OCIRetryMaxAttempts:      ociRetryMaxAttemptsFlag,
		OCIRetryMaxWindowSeconds: ociRetryMaxWindowFlag,
		QuantityIncreasesRisk:    quantityIncreasesRiskFlag,
		RuleCategories:           ruleCategoriesFlag,
		Stats:                    statsFlag,
	}

	// always trim macOS' /private prefix
	if runtime.GOOS == "darwin" {
		mc.TrimPrefixes = append(mc.TrimPrefixes, "/private")
	}

	return mc, nil
}

// resolveFormat turns the "auto" output format into the brief terminal
// renderer for the scan command and the full terminal renderer otherwise.
func resolveFormat(format string, args []string) string {
	if format != "auto" {
		return format
	}
	if slices.Contains(args, "scan") {
		return "terminal_brief"
	}
	return "terminal"
}

// ruleFS returns the rule filesystems to compile, adding the third-party
// rules when requested.
func ruleFS(thirdParty bool) []fs.FS {
	rfs := []fs.FS{rules.FS}
	if thirdParty {
		rfs = append(rfs, thirdparty.FS)
	}
	return rfs
}

// scanTargets applies the analyze and scan target flags to mc. Images select
// OCI scanning (images must be scanned via --image or -i); otherwise the
// path arguments are scanned unless --processes selects running processes.
func scanTargets(mc *malcontent.Config, images []string, processes bool, args []string) {
	switch {
	case len(images) > 0:
		mc.OCI = true
		mc.ScanPaths = images
	case !processes:
		mc.ScanPaths = args
	default:
		mc.Processes = true
	}
}

// addProcessPaths appends the commands (paths) of running processes to
// mc.ScanPaths when process scanning is selected.
func addProcessPaths(ctx context.Context, mc *malcontent.Config) error {
	if !mc.Processes {
		return nil
	}
	ps, err := action.ActiveProcesses(ctx)
	if err != nil {
		return err
	}
	for _, p := range ps {
		// in the future, we'll also want to attach process info directly
		mc.ScanPaths = append(mc.ScanPaths, p.ScanPath)
	}
	return nil
}

// analyze fully interrogates the selected targets and renders every finding.
func (st *cliState) analyze(ctx context.Context, c *cli.Command) error {
	scanTargets(&st.mc, c.StringSlice("image"), c.Bool("processes"), c.Args().Slice())
	if err := addProcessPaths(ctx, &st.mc); err != nil {
		st.returnCode = ExitActionFailed
		return err
	}

	res, err := action.Scan(ctx, st.mc)
	if err != nil {
		st.returnCode = ExitActionFailed
		return err
	}

	if err := st.renderer.Full(ctx, &st.mc, res); err != nil {
		st.returnCode = ExitRenderFailed
		return err
	}
	return nil
}

// diff scans two paths and renders the differences between them.
func (st *cliState) diff(ctx context.Context, c *cli.Command) error {
	sensitivity := c.Int("sensitivity")

	switch {
	case c.Bool("file-risk-change"), sensitivity == 1:
		st.mc.FileRiskChange = true
	case c.Bool("file-risk-increase"):
		st.mc.FileRiskIncrease = true
	default:
	}

	// Allow for images to be scanned with the file risk flags
	if c.Bool("image") {
		st.mc.OCI = true
	}
	if c.Bool("report") {
		st.mc.Report = true
	}

	st.mc.Sensitivity = sensitivity
	st.mc.ScanPaths = c.Args().Slice()

	res, err := action.Diff(ctx, st.mc, st.log)
	if err != nil {
		st.returnCode = ExitActionFailed
		return err
	}

	if err := st.renderer.Full(ctx, &st.mc, res); err != nil {
		st.returnCode = ExitRenderFailed
		return err
	}
	return nil
}

// refreshTestData regenerates the sample test data from the samples checkout.
func (st *cliState) refreshTestData(ctx context.Context, _ *cli.Command) error {
	cfg := refresh.Config{
		Concurrency:  runtime.NumCPU(),
		SamplesPath:  "./out/chainguard-sandbox/malcontent-samples",
		TestDataPath: "./tests",
	}
	if err := refresh.Refresh(ctx, cfg, st.log); err != nil {
		st.returnCode = ExitInputOutput
		return err
	}
	return nil
}

// scan tersely scans the selected targets and renders the findings of the
// highest severity.
func (st *cliState) scan(ctx context.Context, c *cli.Command) error {
	st.mc.Scan = true
	scanTargets(&st.mc, c.StringSlice("image"), c.Bool("processes"), c.Args().Slice())
	if err := addProcessPaths(ctx, &st.mc); err != nil {
		st.returnCode = ExitActionFailed
		return fmt.Errorf("process paths: %w", err)
	}

	// The interactive renderer shows whatever was scanned, so a scan error
	// does not stop it.
	res, err := action.Scan(ctx, st.mc)
	if err != nil && st.renderer.Name() != "Interactive" {
		st.returnCode = ExitActionFailed
		return fmt.Errorf("scan: %w", err)
	}

	files := 0
	if res != nil && res.Files != nil {
		files = res.Files.Size()
	}

	if err := st.renderer.Full(ctx, &st.mc, res); err != nil {
		st.returnCode = ExitRenderFailed
		return err
	}

	if showAnalyzeHint(st.renderer.Name(), files) {
		fmt.Fprintf(os.Stderr, "\n💡 For detailed analysis, try \"mal analyze <path>\"\n")
	}

	return nil
}

// showAnalyzeHint reports whether scan output should suggest running analyze:
// only when files were reported and the renderer writes for a terminal reader.
func showAnalyzeHint(renderer string, files int) bool {
	return files > 0 && (renderer == "Simple" || strings.Contains(renderer, "Terminal"))
}

// splitAndTrimCSV parses a comma-separated flag value into a []string with
// whitespace-trimmed, non-empty entries. Returns nil for an empty input so
// downstream code (which treats nil and empty as identical no-ops) can
// distinguish "flag unset" cases without extra ceremony.
func splitAndTrimCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// handleContext gracefully handles context cancellations.
func handleContext(cancel context.CancelFunc, logger *clog.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	awaitShutdown(sigCh, cancel, logger, drainTimeout, os.Exit)
}

// awaitShutdown waits for a signal on sigCh, cancels in-flight work, and calls
// exit(1) if the process is still running once timeout has passed.
func awaitShutdown(sigCh <-chan os.Signal, cancel context.CancelFunc, logger *clog.Logger, timeout time.Duration, exit func(int)) {
	sig := <-sigCh
	logger.Debug("received signal", slog.Any("signal", sig))
	cancel()

	// Force exit after timeout
	time.AfterFunc(timeout, func() {
		logger.Warn("force exit: drain timeout exceeded, unrendered matches may be discarded", slog.Duration("timeout", timeout))
		logger.Error("forced exit after timeout")
		exit(1)
	})
}
