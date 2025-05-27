// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"context"
	"io"
	"io/fs"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// Renderer is a common interface for Renderers.
type Renderer interface {
	Scanning(context.Context, string)
	File(context.Context, *FileReport) error
	Full(context.Context, *Config, *Report) error
	Name() string
}

type Config struct {
	Concurrency           int
	ExitExtraction        bool
	ExitFirstHit          bool
	ExitFirstMiss         bool
	FileRiskChange        bool
	FileRiskIncrease      bool
	IgnoreSelf            bool
	IgnoreTags            []string
	IncludeDataFiles      bool
	MinFileRisk           int
	MinRisk               int
	OCI                   bool
	Output                io.Writer
	Processes             bool
	QuantityIncreasesRisk bool
	Renderer              Renderer
	RuleFS                []fs.FS
	Rules                 *yarax.Rules
	Scan                  bool
	ScanPaths             []string
	Stats                 bool
	TrimPrefixes          []string
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

type Report struct {
	Files  sync.Map
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
