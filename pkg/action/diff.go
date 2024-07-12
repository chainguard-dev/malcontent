// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"

	"github.com/agext/levenshtein"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/clog"
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
	for _, f := range fromReport.Files {
		if f.Skipped != "" || f.Error != "" {
			continue
		}
		fromRelPath[fromPath] = f
	}

	return fromRelPath, nil
}

func Diff(ctx context.Context, c bincapz.Config) (*bincapz.Report, error) {
	if len(c.ScanPaths) != 2 {
		return nil, fmt.Errorf("diff mode requires 2 paths, you passed in %d path(s)", len(c.ScanPaths))
	}

	src, err := relFileReport(ctx, c, c.ScanPaths[0])
	if err != nil {
		return nil, err
	}

	dest, err := relFileReport(ctx, c, c.ScanPaths[1])
	if err != nil {
		return nil, err
	}

	d := &bincapz.DiffReport{
		Added:    map[string]*bincapz.FileReport{},
		Removed:  map[string]*bincapz.FileReport{},
		Modified: map[string]*bincapz.FileReport{},
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
			d.Removed[relPath] = fr
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

	d.Modified[relPath] = rbs
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
			d.Added[relPath] = tr
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
	if _, exists := d.Modified[relPath]; !exists {
		d.Modified[relPath] = abs
	} else {
		d.Modified[relPath].Behaviors = append(d.Modified[relPath].Behaviors, abs.Behaviors...)
	}
}

type diffReports struct {
	Added     string
	AddedFR   *bincapz.FileReport
	Removed   string
	RemovedFR *bincapz.FileReport
}

// combineReports builds a flattened slice of added and removed paths and their respective file reports.
func combineReports(d *bincapz.DiffReport) []diffReports {
	diffs := make(chan diffReports)
	var wg sync.WaitGroup

	for rpath, rfr := range d.Removed {
		wg.Add(1)
		go func(path string, fr *bincapz.FileReport) {
			defer wg.Done()
			for apath, afr := range d.Added {
				diffs <- diffReports{
					Added:     apath,
					AddedFR:   afr,
					Removed:   path,
					RemovedFR: fr,
				}
			}
		}(rpath, rfr)
	}
	go func() {
		wg.Wait()
		close(diffs)
	}()

	var reports []diffReports
	for diff := range diffs {
		reports = append(reports, diff)
	}
	return reports
}

func inferMoves(ctx context.Context, c bincapz.Config, d *bincapz.DiffReport) {
	flattenedDiffs := combineReports(d)

	for _, fd := range flattenedDiffs {
		score := levenshtein.Match(fd.Removed, fd.Added, levenshtein.NewParams())
		fileMove(ctx, c, fd.RemovedFR, fd.AddedFR, fd.Removed, fd.Added, score, d)
	}
}

func fileMove(ctx context.Context, c bincapz.Config, fr, tr *bincapz.FileReport, rpath, apath string, score float64, d *bincapz.DiffReport) {
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

	// Move these into the modified list if the files are not completely different (something like ~0.3)
	if score > 0.3 {
		d.Modified[apath] = abs
		delete(d.Removed, rpath)
		delete(d.Added, apath)
	}
}
