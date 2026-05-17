// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/puzpuzpuz/xsync/v4"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// KeepalivePolicy selects how the OCI HTTP transport configures keepalives.
type KeepalivePolicy string

const (
	KeepalivePolicyGoDefault          KeepalivePolicy = "go-default"
	KeepalivePolicyExplicitlyEnabled  KeepalivePolicy = "enabled"
	KeepalivePolicyExplicitlyDisabled KeepalivePolicy = "disabled"
)

func (p KeepalivePolicy) IsValid() bool {
	switch p {
	case "", KeepalivePolicyGoDefault, KeepalivePolicyExplicitlyEnabled, KeepalivePolicyExplicitlyDisabled:
		return true
	}
	return false
}

// ParseKeepalivePolicy maps a string to a KeepalivePolicy. Empty input maps to go-default.
func ParseKeepalivePolicy(s string) (KeepalivePolicy, error) {
	switch s {
	case "", "go-default":
		return KeepalivePolicyGoDefault, nil
	case "enabled":
		return KeepalivePolicyExplicitlyEnabled, nil
	case "disabled":
		return KeepalivePolicyExplicitlyDisabled, nil
	}
	return "", fmt.Errorf("invalid keepalive policy %q: expected one of go-default, enabled, disabled", s)
}

// Renderer is a common interface for Renderers.
type Renderer interface {
	Scanning(context.Context, string)
	File(context.Context, *FileReport) error
	Full(context.Context, *Config, *Report) error
	Name() string
}

type Config struct {
	Concurrency    int
	ExitExtraction bool
	// ExitOnExtractorPanic: when true, fail-loud on extractor panic by
	// terminating the process after the panic is logged. Zero-value false
	// preserves the historical catch-and-continue behavior.
	ExitOnExtractorPanic bool
	ExitFirstHit         bool
	ExitFirstMiss        bool
	FileRiskChange       bool
	FileRiskIncrease     bool
	IgnoreSelf           bool
	IgnoreTags           []string
	IncludeDataFiles     bool
	// MaxArchiveBytes caps the total uncompressed bytes produced by archive
	// extraction. Zero means use file.DefaultMaxArchiveBytes.
	MaxArchiveBytes int64
	// MaxArchiveRatio caps the uncompressed:compressed expansion ratio.
	// Zero means use file.DefaultMaxArchiveRatio.
	MaxArchiveRatio float64
	MaxDepth        int
	MaxImageSize    int64
	MaxScanFiles    int
	MinFileRisk     int
	MinRisk         int
	OCI             bool
	OCIAuth         bool
	// OCI transport hardening fields. Zero values trigger sane defaults inside prepareImage; configure via With... setters or environment.
	OCIPullTimeoutSeconds    int
	OCIRetryMaxAttempts      int
	OCIRetryMaxWindowSeconds int
	OCIPerHostSlots          int
	OCIKeepalivePolicy       KeepalivePolicy
	OCIKeepaliveSeconds      int
	OCIProxyOptIn            bool
	OCICABundlePath          string
	Output                   io.Writer
	Processes                bool
	QuantityIncreasesRisk    bool
	Renderer                 Renderer
	Report                   bool
	RuleCategories           []string
	RuleFS                   []fs.FS
	Rules                    *yarax.Rules
	Scan                     bool
	ScanPaths                []string
	Sensitivity              int
	Skipped                  *xsync.Map[string, struct{}]
	Stats                    bool
	TrimPrefixes             []string
}

// configCtxKey is the unexported key used to attach a *Config to a context.
type configCtxKey struct{}

// ContextWithConfig stores c on ctx. The returned context is safe to pass to
// any helper that may need extractor configuration (e.g., recoverExtractor).
func ContextWithConfig(ctx context.Context, c *Config) context.Context {
	return context.WithValue(ctx, configCtxKey{}, c)
}

// ConfigFromContext returns the *Config previously attached via
// ContextWithConfig, or nil if none is present.
func ConfigFromContext(ctx context.Context) *Config {
	c, _ := ctx.Value(configCtxKey{}).(*Config)
	return c
}

type Behavior struct {
	Description string `json:",omitempty" yaml:",omitempty"`
	// MatchStrings are all strings found relating to this behavior
	MatchStrings []string `json:",omitempty" yaml:",omitempty"`
	RiskScore    int
	RiskLevel    string `json:",omitempty" yaml:",omitempty"`

	RuleURL      string `json:",omitempty" yaml:",omitempty"`
	ReferenceURL string `json:",omitempty" yaml:",omitempty"`

	RuleAuthor    string `json:",omitempty" yaml:",omitempty"`
	RuleAuthorURL string `json:",omitempty" yaml:",omitempty"`

	RuleLicense    string `json:",omitempty" yaml:",omitempty"`
	RuleLicenseURL string `json:",omitempty" yaml:",omitempty"`

	DiffAdded   bool `json:",omitempty" yaml:",omitempty"`
	DiffRemoved bool `json:",omitempty" yaml:",omitempty"`

	// ID is the original map key from map[string]*Behavior
	ID string `json:",omitempty" yaml:",omitempty"`

	// Name is the value of m.Rule
	RuleName string `json:",omitempty" yaml:",omitempty"`

	// The name of the rule(s) this behavior overrides
	Override []string `json:",omitempty" yaml:",omitempty"`
}

type FileReport struct {
	Path   string
	SHA256 string
	Size   int64
	// compiler -> x
	Skipped           string            `json:",omitempty" yaml:",omitempty"`
	Meta              map[string]string `json:",omitempty" yaml:",omitempty"`
	Syscalls          []string          `json:",omitempty" yaml:",omitempty"`
	Pledge            []string          `json:",omitempty" yaml:",omitempty"`
	Capabilities      []string          `json:",omitempty" yaml:",omitempty"`
	Behaviors         []*Behavior       `json:",omitempty" yaml:",omitempty"`
	FilteredBehaviors int               `json:",omitempty" yaml:",omitempty"`

	// The absolute path we think this moved fron
	PreviousPath string `json:",omitempty" yaml:",omitempty"`
	// The relative path we think this moved from.
	PreviousRelPath string `json:",omitempty" yaml:",omitempty"`
	// The levenshtein distance between the previous path and the current path
	PreviousRelPathScore float64 `json:",omitempty" yaml:",omitempty"`
	PreviousRiskScore    int     `json:",omitempty" yaml:",omitempty"`
	PreviousRiskLevel    string  `json:",omitempty" yaml:",omitempty"`

	RiskScore int
	RiskLevel string `json:",omitempty" yaml:",omitempty"`

	IsMalcontent bool `json:",omitempty" yaml:",omitempty"`

	Overrides []*Behavior `json:",omitempty" yaml:",omitempty"`

	// Diffing archives is less straightforward than single files
	// Store additional paths to help with relative pathing
	ArchiveRoot string `json:",omitempty" yaml:",omitempty"`
	FullPath    string `json:",omitempty" yaml:",omitempty"`
}

type DiffReport struct {
	Added    *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
	Removed  *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
	Modified *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
}

type ScanResult struct {
	FileReports map[string]*FileReport `json:"Files,omitempty" yaml:"Files,omitempty"`
}

type Report struct {
	Files  *xsync.Map[string, *FileReport]
	Diff   *DiffReport
	Filter string
}

type IntMetric struct {
	Count int
	Key   int
	Total int
	Value float64
}

type StrMetric struct {
	Count int
	Key   string
	Total int
	Value float64
}

type CombinedReport struct {
	Added     string
	AddedFR   *FileReport
	Removed   string
	RemovedFR *FileReport
	Score     float64
}
