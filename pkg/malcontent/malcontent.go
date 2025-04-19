// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"context"
	"fmt"
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
	ScannerPool           *ScannerPool
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
	Files  sync.Map    `json:",omitempty" yaml:",omitempty"`
	Diff   *DiffReport `json:",omitempty" yaml:",omitempty"`
	Filter string      `json:",omitempty" yaml:",omitempty"`
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

// ScannerPool manages a pool of yara-x scanners.
type ScannerPool struct {
	mu       sync.Mutex
	scanners []*yarax.Scanner
	rules    *yarax.Rules
}

// NewScannerPool creates a new scanner pool.
func NewScannerPool(rules *yarax.Rules, count int) (*ScannerPool, error) {
	if rules == nil {
		return nil, fmt.Errorf("cannot create scanner pool: rules is nil")
	}

	if count < 0 {
		return nil, fmt.Errorf("cannot create scanner pool: invalid count %d", count)
	}

	pool := &ScannerPool{
		scanners: make([]*yarax.Scanner, 0, max(1, count)),
		rules:    rules,
	}

	for i := range count {
		scanner := yarax.NewScanner(rules)
		if scanner == nil {
			return nil, fmt.Errorf("failed to create scanner at index %d", i)
		}
		pool.scanners = append(pool.scanners, scanner)
	}

	return pool, nil
}

// Get returns a scanner from the pool or creates a new one if none are available.
func (p *ScannerPool) Get() (*yarax.Scanner, error) {
	if p == nil {
		return nil, fmt.Errorf("scanner pool is nil")
	}

	if p.rules == nil {
		return nil, fmt.Errorf("scanner pool has nil rules")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.scanners) == 0 {
		scanner := yarax.NewScanner(p.rules)
		if scanner == nil {
			return nil, fmt.Errorf("failed to create new scanner")
		}
		return scanner, nil
	}

	lastIdx := len(p.scanners) - 1
	scanner := p.scanners[lastIdx]
	p.scanners = p.scanners[:lastIdx]

	if scanner == nil {
		scanner = yarax.NewScanner(p.rules)
		if scanner == nil {
			return nil, fmt.Errorf("failed to create replacement scanner for nil entry")
		}
	}

	return scanner, nil
}

// Put returns a scanner to the pool.
func (p *ScannerPool) Put(scanner *yarax.Scanner) error {
	if p == nil {
		return fmt.Errorf("scanner pool is nil")
	}

	if scanner == nil {
		return fmt.Errorf("cannot put nil scanner into pool")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.scanners = append(p.scanners, scanner)
	return nil
}

// Close cleans up the scanner pool.
func (p *ScannerPool) Close() error {
	if p == nil {
		return fmt.Errorf("scanner pool is nil")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.scanners = nil
	p.rules = nil

	return nil
}

// InitScannerPool initializes a pool of yara-x scanners.
func (c *Config) InitScannerPool() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	if c.ScannerPool != nil {
		return nil
	}

	if c.Rules == nil {
		return fmt.Errorf("cannot initialize scanner pool: Rules is nil")
	}

	concurrency := max(1, c.Concurrency)
	var err error
	c.ScannerPool, err = NewScannerPool(c.Rules, concurrency)
	if err != nil {
		return fmt.Errorf("failed to initialize scanner pool: %w", err)
	}

	return nil
}

// GetScanner returns a scanner from the pool.
func (c *Config) GetScanner() (*yarax.Scanner, error) {
	if c == nil {
		return nil, fmt.Errorf("config is nil")
	}

	if c.ScannerPool == nil {
		if err := c.InitScannerPool(); err != nil {
			return nil, fmt.Errorf("failed to initialize scanner pool: %w", err)
		}
	}

	return c.ScannerPool.Get()
}

// PutScanner returns a scanner to the pool.
func (c *Config) PutScanner(scanner *yarax.Scanner) error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	if c.ScannerPool == nil {
		return fmt.Errorf("scanner pool is nil")
	}

	return c.ScannerPool.Put(scanner)
}
