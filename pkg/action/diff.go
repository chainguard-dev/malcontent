// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/agext/levenshtein"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/clog"
)

func relFileReport(ctx context.Context, c Config, path string) (map[string]bincapz.FileReport, error) {
	logger := clog.FromContext(ctx).With("path", path)
	fromPath := path
	fromConfig := c
	fromConfig.Renderer = nil
	fromConfig.ScanPaths = []string{fromPath}
	fromReport, err := Scan(ctx, fromConfig)
	if err != nil {
		return nil, err
	}
	fromRelPath := map[string]bincapz.FileReport{}
	for fname, f := range fromReport.Files {
		if f.Skipped != "" || f.Error != "" {
			continue
		}
		logger.Info("file report", slog.String("file", fname), slog.Any("report", f))
		rel, err := filepath.Rel(fromPath, f.Path)
		if err != nil {
			return nil, fmt.Errorf("rel(%q,%q): %w", fromPath, f.Path, err)
		}
		fromRelPath[rel] = f
		logger.Info("relative file report", slog.String("relpath", rel), slog.Any("report", f))
	}

	return fromRelPath, nil
}

func Diff(ctx context.Context, c Config) (*bincapz.Report, error) {
	clog.InfoContext(ctx, "diffing", slog.Any("scanpaths", c.ScanPaths))
	if len(c.ScanPaths) != 2 {
		return nil, fmt.Errorf("diff mode requires 2 paths, you passed in %d path(s)", len(c.ScanPaths))
	}
	from, err := relFileReport(ctx, c, c.ScanPaths[0])
	if err != nil {
		return nil, err
	}

	to, err := relFileReport(ctx, c, c.ScanPaths[1])
	if err != nil {
		return nil, err
	}

	d := bincapz.DiffReport{
		Added:    map[string]bincapz.FileReport{},
		Removed:  map[string]bincapz.FileReport{},
		Modified: map[string]bincapz.FileReport{},
	}

	// things that appear in the source
	for relPath, fr := range from {
		tr, exists := to[relPath]
		if !exists {
			d.Removed[relPath] = fr
			continue
		}
		// This file exists in both source & destination
		rbs := bincapz.FileReport{
			Path:              tr.Path,
			Behaviors:         map[string]bincapz.Behavior{},
			PreviousRiskScore: fr.RiskScore,
			PreviousRiskLevel: fr.RiskLevel,
			RiskLevel:         tr.RiskLevel,
			RiskScore:         tr.RiskScore,
		}

		// if source behavior is not in the destination
		for key, b := range fr.Behaviors {
			if _, exists := tr.Behaviors[key]; !exists {
				b.DiffRemoved = true
				rbs.Behaviors[key] = b
			}
		}

		d.Modified[relPath] = rbs
	}

	// things that exist in the destination
	for relPath, tr := range to {
		fr, exists := from[relPath]
		if !exists {
			d.Added[relPath] = tr
			continue
		}

		// This file exists in both source and destination
		abs := bincapz.FileReport{
			Path:              tr.Path,
			Behaviors:         map[string]bincapz.Behavior{},
			PreviousRiskScore: fr.RiskScore,
			PreviousRiskLevel: fr.RiskLevel,

			RiskScore: tr.RiskScore,
			RiskLevel: tr.RiskLevel,
		}

		// if destination behavior is not in the source
		for key, b := range tr.Behaviors {
			if _, exists := fr.Behaviors[key]; !exists {
				b.DiffAdded = true
				abs.Behaviors[key] = b
			}
		}

		// are there already modified behaviors for this file?
		if _, exists := d.Modified[relPath]; !exists {
			d.Modified[relPath] = abs
		} else {
			for key, b := range abs.Behaviors {
				d.Modified[relPath].Behaviors[key] = b
			}
		}
	}

	// Walk over the added/removed paths and infer moves based on the
	// levenshtein distance of the file names.  If the distance is a 90+% match,
	// then treat it as a move.
	for rpath, fr := range d.Removed {
		for apath, tr := range d.Added {
			score := levenshtein.Match(rpath, apath, levenshtein.NewParams())
			if score < 0.9 {
				continue
			}

			// We think that this file moved from rpath to apath.
			abs := bincapz.FileReport{
				Path:                 tr.Path,
				PreviousRelPath:      rpath,
				PreviousRelPathScore: score,

				Behaviors:         map[string]bincapz.Behavior{},
				PreviousRiskScore: fr.RiskScore,
				PreviousRiskLevel: fr.RiskLevel,

				RiskScore: tr.RiskScore,
				RiskLevel: tr.RiskLevel,
			}

			// if destination behavior is not in the source
			for key, b := range tr.Behaviors {
				if _, exists := fr.Behaviors[key]; !exists {
					b.DiffAdded = true
					abs.Behaviors[key] = b
				}
			}

			// if source behavior is not in the destination
			for key, b := range fr.Behaviors {
				if _, exists := tr.Behaviors[key]; !exists {
					b.DiffRemoved = true
					abs.Behaviors[key] = b
				}
			}

			// Move these into the modified list.
			d.Modified[apath] = abs
			delete(d.Removed, rpath)
			delete(d.Added, apath)
		}
	}

	clog.FromContext(ctx).Info("diff result", slog.Any("diff", d))

	r := &bincapz.Report{
		Diff: d,
	}

	return r, err
}
