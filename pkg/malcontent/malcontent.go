// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"context"
	"io"

	"github.com/hillu/go-yara/v4"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// Renderer is a common interface for Renderers.
type Renderer interface {
	File(context.Context, *FileReport) error
	Full(context.Context, *Report) error
}

type Config struct {
	Concurrency           int
	ErrFirstHit           bool
	ErrFirstMiss          bool
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
	Rules                 *yara.Rules
	Scan                  bool
	ScanPaths             []string
	Stats                 bool
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
}

type FileReport struct {
	Path   string
	SHA256 string
	Size   int64
	// compiler -> x
	Error             string            `json:",omitempty" yaml:",omitempty"`
	Skipped           string            `json:",omitempty" yaml:",omitempty"`
	Meta              map[string]string `json:",omitempty" yaml:",omitempty"`
	Syscalls          []string          `json:",omitempty" yaml:",omitempty"`
	Pledge            []string          `json:",omitempty" yaml:",omitempty"`
	Capabilities      []string          `json:",omitempty" yaml:",omitempty"`
	Behaviors         []*Behavior       `json:",omitempty" yaml:",omitempty"`
	FilteredBehaviors int               `json:",omitempty" yaml:",omitempty"`

	// The relative path we think this moved from.
	PreviousRelPath string `json:",omitempty" yaml:",omitempty"`
	// The levenshtein distance between the previous path and the current path
	PreviousRelPathScore float64 `json:",omitempty" yaml:",omitempty"`
	PreviousRiskScore    int     `json:",omitempty" yaml:",omitempty"`
	PreviousRiskLevel    string  `json:",omitempty" yaml:",omitempty"`

	RiskScore int
	RiskLevel string `json:",omitempty" yaml:",omitempty"`

	IsMalcontent bool `json:",omitempty" yaml:",omitempty"`
}

type DiffReport struct {
	Added    *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
	Removed  *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
	Modified *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
}

type Report struct {
	Files  *orderedmap.OrderedMap[string, *FileReport] `json:",omitempty" yaml:",omitempty"`
	Diff   *DiffReport                                 `json:",omitempty" yaml:",omitempty"`
	Filter string                                      `json:",omitempty" yaml:",omitempty"`
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
