// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/agext/levenshtein"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/clog"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"golang.org/x/sync/errgroup"
)

func relFileReport(ctx context.Context, c bincapz.Config, fromPath string) (map[string]*bincapz.FileReport, error) {
	fromConfig := c
	fromConfig.Renderer = nil
	fromConfig.ScanPaths = []string{fromPath}
	fromReport, err := recursiveScan(ctx, fromConfig)
	if err != nil {
		return nil, err
	}
	fromRelPath := map[string]*bincapz.FileReport{}
	for files := fromReport.Files.Oldest(); files != nil; files = files.Next() {
		if files.Value.Skipped != "" || files.Value.Error != "" {
			continue
		}
		rel, err := filepath.Rel(fromPath, files.Value.Path)
		if err != nil {
			return nil, fmt.Errorf("rel(%q,%q): %w", fromPath, files.Value.Path, err)
		}
		fromRelPath[rel] = files.Value
	}

	return fromRelPath, nil
}

func Diff(ctx context.Context, c bincapz.Config) (*bincapz.Report, error) {
	if len(c.ScanPaths) != 2 {
		return nil, fmt.Errorf("diff mode requires 2 paths, you passed in %d path(s)", len(c.ScanPaths))
	}

	var g errgroup.Group
	g.SetLimit(2) // create src and dest relFileReports concurrently

	var src, dest map[string]*bincapz.FileReport
	var err error
	g.Go(func() error {
		src, err = relFileReport(ctx, c, c.ScanPaths[0])
		if err != nil {
			return err
		}
		return nil
	})

	g.Go(func() error {
		dest, err = relFileReport(ctx, c, c.ScanPaths[1])
		if err != nil {
			return err
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	d := &bincapz.DiffReport{
		Added:    orderedmap.New[string, *bincapz.FileReport](),
		Removed:  orderedmap.New[string, *bincapz.FileReport](),
		Modified: orderedmap.New[string, *bincapz.FileReport](),
	}

	processSrc(ctx, c, src, dest, d)
	processDest(ctx, c, src, dest, d)
	// skip inferring moves if added and removed are empty
	if d.Added != nil && d.Removed != nil {
		inferMoves(ctx, c, d)
	}
	return &bincapz.Report{Diff: d}, err
}

func processSrc(ctx context.Context, c bincapz.Config, src, dest map[string]*bincapz.FileReport, d *bincapz.DiffReport) {
	// things that appear in the source
	for relPath, fr := range src {
		tr, exists := dest[relPath]
		if !exists {
			d.Removed.Set(relPath, fr)
			continue
		}
		handleFile(ctx, c, fr, tr, relPath, d)
	}
}

func handleFile(ctx context.Context, c bincapz.Config, fr, tr *bincapz.FileReport, relPath string, d *bincapz.DiffReport) {
	// We've now established that file exists in both source & destination
	if fr.RiskScore < c.MinFileRisk && tr.RiskScore < c.MinFileRisk {
		clog.FromContext(ctx).Info("diff does not meet min trigger level", slog.Any("path", tr.Path))
		return
	}

	rbs := createFileReport(tr, fr)

	// if source behavior is not in the destination
	for _, fb := range fr.Behaviors {
		if !behaviorExists(fb, tr.Behaviors) {
			fb.DiffRemoved = true
			rbs.Behaviors = append(rbs.Behaviors, fb)
		}
	}

	d.Modified.Set(relPath, rbs)
}

func createFileReport(tr, fr *bincapz.FileReport) *bincapz.FileReport {
	return &bincapz.FileReport{
		Path:              tr.Path,
		PreviousRelPath:   fr.Path,
		Behaviors:         []*bincapz.Behavior{},
		PreviousRiskScore: fr.RiskScore,
		PreviousRiskLevel: fr.RiskLevel,
		RiskLevel:         tr.RiskLevel,
		RiskScore:         tr.RiskScore,
	}
}

func behaviorExists(b *bincapz.Behavior, behaviors []*bincapz.Behavior) bool {
	for _, tb := range behaviors {
		if tb.ID == b.ID {
			return true
		}
	}
	return false
}

func processDest(ctx context.Context, c bincapz.Config, from, to map[string]*bincapz.FileReport, d *bincapz.DiffReport) {
	// things that exist in the destination
	for relPath, tr := range to {
		fr, exists := from[relPath]
		if !exists {
			d.Added.Set(relPath, tr)
			continue
		}

		fileDestination(ctx, c, fr, tr, relPath, d)
	}
}

func fileDestination(ctx context.Context, c bincapz.Config, fr, tr *bincapz.FileReport, relPath string, d *bincapz.DiffReport) {
	// We've now established that this file exists in both source and destination
	if fr.RiskScore < c.MinFileRisk && tr.RiskScore < c.MinFileRisk {
		clog.FromContext(ctx).Info("diff does not meet min trigger level", slog.Any("path", tr.Path))
		return
	}

	abs := createFileReport(tr, fr)

	// if destination behavior is not in the source
	for _, tb := range tr.Behaviors {
		if !behaviorExists(tb, fr.Behaviors) {
			tb.DiffAdded = true
			abs.Behaviors = append(abs.Behaviors, tb)
		}
	}

	// are there already modified behaviors for this file?
	if _, exists := d.Modified.Get(relPath); !exists {
		d.Modified.Set(relPath, abs)
	} else {
		if rel, exists := d.Modified.Get(relPath); exists {
			rel.Behaviors = append(rel.Behaviors, abs.Behaviors...)
			d.Modified.Set(relPath, rel)
		}
	}
}

// filterMap filters orderedmap pairs by checking for matches against a slice of compiled regular expression patterns.
func filterMap(om *orderedmap.OrderedMap[string, *bincapz.FileReport], ps []*regexp.Regexp, c chan<- *orderedmap.Pair[string, *bincapz.FileReport], wg *sync.WaitGroup) {
	defer wg.Done()
	for pair := om.Oldest(); pair != nil; pair = pair.Next() {
		for _, pattern := range ps {
			if match := pattern.FindString(filepath.Base(pair.Key)); match != "" {
				c <- pair
			}
		}
	}
}

// combine iterates over the removed and added channels to create a diff report to store in the combined channel.
func combine(removed, added <-chan *orderedmap.Pair[string, *bincapz.FileReport], combined chan<- bincapz.CombinedReport, wg *sync.WaitGroup) {
	defer wg.Done()
	for r := range removed {
		for a := range added {
			score := levenshtein.Match(r.Key, a.Key, levenshtein.NewParams())
			if score < 0.9 {
				continue
			}
			combined <- bincapz.CombinedReport{
				Added:     a.Key,
				AddedFR:   a.Value,
				Removed:   r.Key,
				RemovedFR: r.Value,
				Score:     score,
			}
		}
	}
}

// combineReports orchestrates the population of the diffs channel with relevant diffReports.
func combineReports(c bincapz.Config, d *bincapz.DiffReport, combined chan<- bincapz.CombinedReport) {
	defer close(combined)

	maxConcurrency := c.Concurrency
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}

	var wg sync.WaitGroup

	// Patterns we care about when handling diffs
	patterns := []string{
		`^[\w.-]+\.so$`,
		`^.+-.*-r\d+\.spdx\.json$`,
	}

	ps := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		ps[i] = regexp.MustCompile(pattern)
	}

	// Build two channels with filtered paths to iterate through in the worker pool
	removed := make(chan *orderedmap.Pair[string, *bincapz.FileReport], d.Removed.Len())
	added := make(chan *orderedmap.Pair[string, *bincapz.FileReport], d.Added.Len())

	wg.Add(1)
	go func() {
		filterMap(d.Removed, ps, removed, &wg)
		close(removed)
	}()

	wg.Add(1)
	go func() {
		filterMap(d.Added, ps, added, &wg)
		close(added)
	}()

	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		combine(removed, added, combined, &wg)
	}

	wg.Wait()
}

func inferMoves(ctx context.Context, c bincapz.Config, d *bincapz.DiffReport) {
	// Create a channel with enough capacity to hold the entirety of the two maps
	// This is the worst case since we will always filter out irrelevant filepaths
	combined := make(chan bincapz.CombinedReport, d.Removed.Len()+d.Added.Len())

	combineReports(c, d, combined)

	for dr := range combined {
		fileMove(ctx, c, dr.RemovedFR, dr.AddedFR, dr.Removed, dr.Added, d, dr.Score)
	}
}

func fileMove(ctx context.Context, c bincapz.Config, fr, tr *bincapz.FileReport, rpath, apath string, d *bincapz.DiffReport, score float64) {
	minRisk := int(math.Min(float64(c.MinRisk), float64(c.MinFileRisk)))
	if fr.RiskScore < minRisk && tr.RiskScore < minRisk {
		clog.FromContext(ctx).Info("diff does not meet min trigger level", slog.Any("path", tr.Path))
		return
	}

	// We think that this file moved from rpath to apath.
	abs := &bincapz.FileReport{
		Path:                 tr.Path,
		PreviousRelPath:      rpath,
		PreviousRelPathScore: score,

		Behaviors:         []*bincapz.Behavior{},
		PreviousRiskScore: fr.RiskScore,
		PreviousRiskLevel: fr.RiskLevel,

		RiskScore: tr.RiskScore,
		RiskLevel: tr.RiskLevel,
	}

	// if destination behavior is not in the source
	for _, tb := range tr.Behaviors {
		if !behaviorExists(tb, fr.Behaviors) {
			tb.DiffAdded = true
			abs.Behaviors = append(abs.Behaviors, tb)
		}
	}

	// if source behavior is not in the destination
	for _, fb := range fr.Behaviors {
		if !behaviorExists(fb, tr.Behaviors) {
			fb.DiffRemoved = true
			abs.Behaviors = append(abs.Behaviors, fb)
		}
	}

	d.Modified.Set(apath, abs)
	d.Removed.Delete(rpath)
	d.Added.Delete(apath)
}
