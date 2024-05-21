// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"path/filepath"
	"strings"

	"github.com/agext/levenshtein"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/clog"
)

func relFileReport(ctx context.Context, c Config, fromPath string) (map[string]*bincapz.FileReport, error) {
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

		rel, err := filepath.Rel(fromPath, f.Path)
		if err != nil {
			return nil, fmt.Errorf("rel(%q,%q): %w", fromPath, f.Path, err)
		}
		fromRelPath[rel] = f
	}

	return fromRelPath, nil
}

func Diff(ctx context.Context, c Config) (*bincapz.Report, error) {
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
	inferMoves(ctx, c, d)

	return &bincapz.Report{Diff: d}, err
}

func processSrc(ctx context.Context, c Config, src, dest map[string]*bincapz.FileReport, d *bincapz.DiffReport) {
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

func handleFile(ctx context.Context, c Config, fr, tr *bincapz.FileReport, relPath string, d *bincapz.DiffReport) {
	// We've now established that file exists in both source & destination
	if fr.RiskScore < c.MinFileScore && tr.RiskScore < c.MinFileScore {
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

func processDest(ctx context.Context, c Config, from, to map[string]*bincapz.FileReport, d *bincapz.DiffReport) {
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

func fileDestination(ctx context.Context, c Config, fr, tr *bincapz.FileReport, relPath string, d *bincapz.DiffReport) {
	// We've now established that this file exists in both source and destination
	if fr.RiskScore < c.MinFileScore && tr.RiskScore < c.MinFileScore {
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

func inferMoves(ctx context.Context, c Config, d *bincapz.DiffReport) {
	// Walk over the added/removed paths and infer moves based on the
	// levenshtein distance of the file names.  If the distance is a 90+% match,
	// then treat it as a move.
	for rpath, fr := range d.Removed {
		// We only want to consider files that look like shared objects because Match() is slow and this is ~quadratic.
		if !strings.Contains(path.Base(rpath), ".so.") {
			continue
		}

		for apath, tr := range d.Added {
			// See above.
			if !strings.Contains(path.Base(apath), ".so.") {
				continue
			}

			score := levenshtein.Match(rpath, apath, levenshtein.NewParams())
			if score < 0.9 {
				continue
			}

			fileMove(ctx, c, fr, tr, rpath, apath, score, d)
		}
	}
}

func fileMove(ctx context.Context, c Config, fr, tr *bincapz.FileReport, rpath, apath string, score float64, d *bincapz.DiffReport) {
	if fr.RiskScore < c.MinFileScore && tr.RiskScore < c.MinFileScore {
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

	// Move these into the modified list.
	d.Modified[apath] = abs
	delete(d.Removed, rpath)
	delete(d.Added, apath)
}
