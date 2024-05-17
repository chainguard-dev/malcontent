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

	from, err := relFileReport(ctx, c, c.ScanPaths[0])
	if err != nil {
		return nil, err
	}

	to, err := relFileReport(ctx, c, c.ScanPaths[1])
	if err != nil {
		return nil, err
	}

	d := &bincapz.DiffReport{
		Added:    map[string]*bincapz.FileReport{},
		Removed:  map[string]*bincapz.FileReport{},
		Modified: map[string]*bincapz.FileReport{},
	}

	// things that appear in the source
	for relPath, fr := range from {
		tr, exists := to[relPath]
		if !exists {
			d.Removed[relPath] = fr
			continue
		}
		// We've now established that file exists in both source & destination
		if fr.RiskScore < c.MinFileScore && tr.RiskScore < c.MinFileScore {
			clog.FromContext(ctx).Info("diff does not meet min trigger level", slog.Any("path", tr.Path))
			continue
		}

		rbs := &bincapz.FileReport{
			Path:              tr.Path,
			Behaviors:         []*bincapz.Behavior{},
			PreviousRiskScore: fr.RiskScore,
			PreviousRiskLevel: fr.RiskLevel,
			RiskLevel:         tr.RiskLevel,
			RiskScore:         tr.RiskScore,
		}

		// if source behavior is not in the destination
		for _, fb := range fr.Behaviors {
			found := false
			for _, tb := range tr.Behaviors {
				if tb.Evidence == fb.Evidence {
					found = true
					break
				}
			}
			if !found {
				fb.DiffRemoved = true
				rbs.Behaviors = append(rbs.Behaviors, fb)
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

		// We've now established that this file exists in both source and destination
		if fr.RiskScore < c.MinFileScore && tr.RiskScore < c.MinFileScore {
			clog.FromContext(ctx).Info("diff does not meet min trigger level", slog.Any("path", tr.Path))
			continue
		}

		abs := &bincapz.FileReport{
			Path:              tr.Path,
			Behaviors:         []*bincapz.Behavior{},
			PreviousRiskScore: fr.RiskScore,
			PreviousRiskLevel: fr.RiskLevel,

			RiskScore: tr.RiskScore,
			RiskLevel: tr.RiskLevel,
		}

		// if destination behavior is not in the source
		for _, tb := range tr.Behaviors {
			found := false
			for _, fb := range fr.Behaviors {
				if len(fr.Behaviors) > 0 && tb.Evidence == fb.Evidence {
					found = true
					break
				}
			}
			if !found {
				tb.DiffAdded = true
				abs.Behaviors = append(abs.Behaviors, tb)
			}
		}

		// are there already modified behaviors for this file?
		if _, exists := d.Modified[relPath]; !exists {
			d.Modified[relPath] = abs
		} else {
			for _, b := range abs.Behaviors {
				d.Modified[relPath].Behaviors = append(d.Modified[relPath].Behaviors, b)
			}
		}
	}

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

			if fr.RiskScore < c.MinFileScore && tr.RiskScore < c.MinFileScore {
				clog.FromContext(ctx).Info("diff does not meet min trigger level", slog.Any("path", tr.Path))
				continue
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
				found := false
				for _, fb := range fr.Behaviors {
					if len(fr.Behaviors) > 0 && fb.Evidence == tb.Evidence {
						found = true
						break
					}
				}
				if !found {
					tb.DiffAdded = true
					abs.Behaviors = append(abs.Behaviors, tb)
				}
			}

			// if source behavior is not in the destination
			for _, fb := range fr.Behaviors {
				found := false
				for _, tb := range tr.Behaviors {
					if len(fr.Behaviors) > 0 && tb.Evidence == fb.Evidence {
						found = true
						break
					}
				}
				if !found {
					fb.DiffRemoved = true
					abs.Behaviors = append(abs.Behaviors, fb)
				}
			}

			// Move these into the modified list.
			d.Modified[apath] = abs
			delete(d.Removed, rpath)
			delete(d.Added, apath)
		}
	}

	return &bincapz.Report{Diff: d}, err
}
