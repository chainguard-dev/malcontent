// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"runtime"
	"sync"
	"sync/atomic"

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
	MaxScanners           int
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
	ScannerPool           *ScannerPool
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
	Error             string            `json:",omitempty" yaml:",omitempty"`
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

// ScannerPool manages a limited pool of YARA scanners.
type ScannerPool struct {
	mu           sync.Mutex
	rules        *yarax.Rules
	scanners     []*yarax.Scanner
	available    chan *yarax.Scanner
	maxScanners  int32
	currentCount int32
	closed       atomic.Bool
}

// NewScannerPool creates a new scanner pool with a maximum number of scanners.
func NewScannerPool(rules *yarax.Rules, maxScanners int) (*ScannerPool, error) {
	if rules == nil {
		return nil, fmt.Errorf("rules cannot be nil")
	}
	if maxScanners < 1 {
		maxScanners = max(1, runtime.GOMAXPROCS(0)/2)
	}

	// #nosec G115 // ignore converting int to int32
	pool := &ScannerPool{
		rules:       rules,
		available:   make(chan *yarax.Scanner, maxScanners),
		maxScanners: int32(maxScanners),
		scanners:    make([]*yarax.Scanner, 0, maxScanners),
		closed:      atomic.Bool{},
	}

	scanner := yarax.NewScanner(rules)
	if scanner == nil {
		return nil, fmt.Errorf("failed to create scanner")
	}

	pool.available <- scanner
	atomic.AddInt32(&pool.currentCount, 1)

	return pool, nil
}

// createScanner creates a new yarax scanner.
func (p *ScannerPool) createScanner() (*yarax.Scanner, error) {
	if atomic.LoadInt32(&p.currentCount) > p.maxScanners/2 {
		runtime.GC()
	}

	if p.rules == nil {
		return nil, fmt.Errorf("rules not initialized")
	}

	scanner := yarax.NewScanner(p.rules)
	if scanner == nil {
		return nil, fmt.Errorf("failed to create new scanner")
	}

	if err := p.validateScanner(scanner); err != nil {
		scanner.Destroy()
		return nil, err
	}

	return scanner, nil
}

// validateScanner attempts to compile the provided rules.
func (p *ScannerPool) validateScanner(scanner *yarax.Scanner) error {
	if scanner == nil {
		return fmt.Errorf("nil scanner")
	}
	_, err := scanner.Scan([]byte("test"))
	if err != nil {
		return fmt.Errorf("scanner validation failed: %w", err)
	}
	return nil
}

// Get retrieves a scanner from the pool or creates a new one if necessary.
func (p *ScannerPool) Get() (*yarax.Scanner, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("scanner pool is closed")
	}

	// Retrieve an existing scanner
	// If none are available, create up to the maximum number of scanners
	select {
	case scanner := <-p.available:
		return scanner, nil
	default:
		p.mu.Lock()
		if atomic.LoadInt32(&p.currentCount) < p.maxScanners {
			scanner, err := p.createScanner()
			if err != nil {
				p.mu.Unlock()
				return nil, fmt.Errorf("create scanner: %w", err)
			}
			p.scanners = append(p.scanners, scanner)
			atomic.AddInt32(&p.currentCount, 1)
			p.mu.Unlock()
			return scanner, nil
		}
		p.mu.Unlock()

		return <-p.available, nil
	}
}

// Put returns a scanner to the pool.
func (p *ScannerPool) Put(scanner *yarax.Scanner) {
	if scanner == nil || p.closed.Load() {
		return
	}
	p.available <- scanner
}

// Cleanup destroys all scanners in the pool.
func (p *ScannerPool) Cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed.Swap(true) {
		return
	}

	for len(p.available) > 0 {
		if scanner := <-p.available; scanner != nil {
			scanner.Destroy()
		}
	}
	close(p.available)

	for _, scanner := range p.scanners {
		if scanner != nil {
			scanner.Destroy()
		}
	}

	p.scanners = nil
	atomic.StoreInt32(&p.currentCount, 0)
}
