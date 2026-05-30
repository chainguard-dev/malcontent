// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"io"
	"io/fs"
	"runtime"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/puzpuzpuz/xsync/v4"
)

// Option configures a Config produced by New. Options are applied in order
// and may overwrite earlier settings.
type Option func(*Config)

// LibraryDefaults returns a Config preloaded with sane defaults for embedding
// callers, drawn from the malcontent CLI's defaults. Most fields mirror the CLI
// scan defaults; Sensitivity:5 corresponds to the diff/ALL default (the value
// the CLI uses on the diff path) and is inert for scans, which never read
// Sensitivity. Output defaults to io.Discard so library use will not panic on a
// nil writer.
func LibraryDefaults() Config {
	return Config{
		Concurrency:      runtime.NumCPU(),
		MaxDepth:         32,
		MaxImageSize:     1 << 34,
		MaxScanFiles:     1 << 21,
		MinFileRisk:      1,
		MinRisk:          1,
		Sensitivity:      5,
		IncludeDataFiles: false,
		Output:           io.Discard,
	}
}

// New folds opts left-to-right over LibraryDefaults and returns the result.
func New(opts ...Option) Config {
	c := LibraryDefaults()
	for _, o := range opts {
		o(&c)
	}
	return c
}

// Apply folds opts left-to-right over c in place.
func Apply(c *Config, opts ...Option) {
	for _, o := range opts {
		o(c)
	}
}

func WithConcurrency(n int) Option     { return func(c *Config) { c.Concurrency = n } }
func WithExitExtraction(b bool) Option { return func(c *Config) { c.ExitExtraction = b } }
func WithExitOnExtractorPanic(b bool) Option {
	return func(c *Config) { c.ExitOnExtractorPanic = b }
}
func WithExitFirstHit(b bool) Option     { return func(c *Config) { c.ExitFirstHit = b } }
func WithExitFirstMiss(b bool) Option    { return func(c *Config) { c.ExitFirstMiss = b } }
func WithFileRiskChange(b bool) Option   { return func(c *Config) { c.FileRiskChange = b } }
func WithFileRiskIncrease(b bool) Option { return func(c *Config) { c.FileRiskIncrease = b } }
func WithIgnoreSelf(b bool) Option       { return func(c *Config) { c.IgnoreSelf = b } }

// WithIgnoreTags retains the caller's reference; do not mutate after Apply.
func WithIgnoreTags(tags []string) Option  { return func(c *Config) { c.IgnoreTags = tags } }
func WithIncludeDataFiles(b bool) Option   { return func(c *Config) { c.IncludeDataFiles = b } }
func WithMaxArchiveBytes(n int64) Option   { return func(c *Config) { c.MaxArchiveBytes = n } }
func WithMaxArchiveRatio(r float64) Option { return func(c *Config) { c.MaxArchiveRatio = r } }
func WithMaxDepth(n int) Option            { return func(c *Config) { c.MaxDepth = n } }
func WithMaxImageSize(n int64) Option      { return func(c *Config) { c.MaxImageSize = n } }
func WithMaxScanFiles(n int) Option        { return func(c *Config) { c.MaxScanFiles = n } }
func WithMinFileRisk(n int) Option         { return func(c *Config) { c.MinFileRisk = n } }
func WithMinRisk(n int) Option             { return func(c *Config) { c.MinRisk = n } }
func WithOCI(b bool) Option                { return func(c *Config) { c.OCI = b } }
func WithOCIAuth(b bool) Option            { return func(c *Config) { c.OCIAuth = b } }

func WithOCIPullTimeoutSeconds(n int) Option {
	return func(c *Config) { c.OCIPullTimeoutSeconds = n }
}

func WithOCIRetryMaxAttempts(n int) Option {
	return func(c *Config) { c.OCIRetryMaxAttempts = n }
}

func WithOCIRetryMaxWindowSeconds(n int) Option {
	return func(c *Config) { c.OCIRetryMaxWindowSeconds = n }
}
func WithOCIPerHostSlots(n int) Option { return func(c *Config) { c.OCIPerHostSlots = n } }

// WithOCIKeepalivePolicy selects whether the OCI transport leaves keepalives at
// Go defaults, explicitly enables them with the supplied idle timeout in
// seconds, or explicitly disables them. seconds is only consulted when
// p == KeepalivePolicyExplicitlyEnabled.
func WithOCIKeepalivePolicy(p KeepalivePolicy, seconds int) Option {
	return func(c *Config) {
		c.OCIKeepalivePolicy = p
		c.OCIKeepaliveSeconds = seconds
	}
}
func WithOCIProxyOptIn(b bool) Option { return func(c *Config) { c.OCIProxyOptIn = b } }

// WithOCICABundlePath selects the OCI registry CA bundle. The sentinel
// "system" (and empty string) selects the OS trust store; any other value
// must be an absolute path to a PEM bundle.
func WithOCICABundlePath(s string) Option { return func(c *Config) { c.OCICABundlePath = s } }

// WithOutput retains the caller's reference; do not mutate after Apply.
func WithOutput(w io.Writer) Option { return func(c *Config) { c.Output = w } }
func WithProcesses(b bool) Option   { return func(c *Config) { c.Processes = b } }
func WithQuantityIncreasesRisk(b bool) Option {
	return func(c *Config) { c.QuantityIncreasesRisk = b }
}

// WithRenderer retains the caller's reference; do not mutate after Apply.
func WithRenderer(r Renderer) Option { return func(c *Config) { c.Renderer = r } }
func WithReport(b bool) Option       { return func(c *Config) { c.Report = b } }

// WithRuleCategories retains the caller's reference; do not mutate after Apply.
func WithRuleCategories(cats []string) Option { return func(c *Config) { c.RuleCategories = cats } }

// WithRuleFS retains the caller's reference; do not mutate after Apply.
func WithRuleFS(rfs []fs.FS) Option { return func(c *Config) { c.RuleFS = rfs } }

// WithRules retains the caller's reference; do not mutate after Apply.
func WithRules(r *yarax.Rules) Option { return func(c *Config) { c.Rules = r } }
func WithScan(b bool) Option          { return func(c *Config) { c.Scan = b } }

// WithScanPaths retains the caller's reference; do not mutate after Apply.
func WithScanPaths(paths []string) Option { return func(c *Config) { c.ScanPaths = paths } }
func WithSensitivity(n int) Option        { return func(c *Config) { c.Sensitivity = n } }

// WithSkipped retains the caller's reference; do not mutate after Apply.
func WithSkipped(m *xsync.Map[string, struct{}]) Option {
	return func(c *Config) { c.Skipped = m }
}
func WithStats(b bool) Option { return func(c *Config) { c.Stats = b } }

// WithTrimPrefixes retains the caller's reference; do not mutate after Apply.
func WithTrimPrefixes(p []string) Option { return func(c *Config) { c.TrimPrefixes = p } }
