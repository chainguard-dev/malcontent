// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agext/levenshtein"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"golang.org/x/sync/errgroup"
)

// displayPath mimics diff(1) output for relative paths.
func displayPath(base, path string) string {
	if filepath.IsAbs(path) {
		rel, err := filepath.Rel(base, path)
		if err == nil {
			return rel
		}
	}
	return path
}

// relPath returns the cleanest possible relative path between a source path and files within said path.
func relPath(from string, fr *malcontent.FileReport, isArchive bool) (string, string, error) {
	var base string
	var err error
	var rel string
	switch {
	case isArchive:
		fromRoot := fr.ArchiveRoot
		base = fr.FullPath
		// trim archiveRoot from fullPath
		archiveFile := strings.TrimPrefix(fr.FullPath, fr.ArchiveRoot)
		rel, err = filepath.Rel(fromRoot, archiveFile)
		if err != nil {
			return "", "", err
		}
	default:
		base, err = filepath.Abs(from)
		if err != nil {
			return "", "", err
		}
		info, err := os.Stat(from)
		if err != nil {
			return "", "", err
		}
		dir := filepath.Dir(from)
		// Evaluate symlinks to cover edge cases like macOS' /private/tmp -> /tmp symlink
		// Also, remove any filenames to correctly determine the relative path
		// Using "." and "." will show as modifications for completely unrelated files and paths
		var fromRoot string
		if info.IsDir() {
			fromRoot, err = filepath.EvalSymlinks(from)
		} else {
			fromRoot, err = filepath.EvalSymlinks(dir)
		}
		if err != nil {
			return "", "", err
		}
		if fromRoot == "." {
			fromRoot = from
		}
		rel, err = filepath.Rel(fromRoot, fr.Path)
		if err != nil {
			return "", "", err
		}
	}
	return rel, base, nil
}

func relFileReport(ctx context.Context, c malcontent.Config, fromPath string) (map[string]*malcontent.FileReport, string, error) {
	fromConfig := c
	fromConfig.Renderer = nil
	fromConfig.ScanPaths = []string{fromPath}
	fromReport, err := recursiveScan(ctx, fromConfig)
	if err != nil {
		return nil, "", err
	}
	fromRelPath := map[string]*malcontent.FileReport{}
	var base, rel string
	fromReport.Files.Range(func(key, value any) bool {
		if key == nil || value == nil {
			return true
		}
		if fr, ok := value.(*malcontent.FileReport); ok {
			isArchive := fr.ArchiveRoot != ""
			if fr.Skipped != "" || fr.Error != "" {
				return true
			}
			rel, base, err = relPath(fromPath, fr, isArchive)
			if err != nil {
				return false
			}
			fromRelPath[rel] = fr
		}
		return true
	})

	return fromRelPath, base, nil
}

// scoreFile returns a boolean to determine how individual files are stored in a diff report.
func scoreFile(fr, tr *malcontent.FileReport) bool {
	scoreSrc := false
	scoreDest := false

	patterns := []string{
		`^[\w.-]+\.so$`,
		`^.+-.*-r\d+\.spdx\.json$`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(fr.Path) {
			scoreSrc = true
		}
		if re.MatchString(tr.Path) {
			scoreDest = true
		}
	}

	// If both files match patterns, reeturn true to indicate that `inferMoves` should be used
	// Otherwise, indicate that `handleFile` should be used
	if scoreSrc && scoreDest {
		return true
	}
	return false
}

func Diff(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	if len(c.ScanPaths) != 2 {
		return nil, fmt.Errorf("diff mode requires 2 paths, you passed in %d path(s)", len(c.ScanPaths))
	}

	srcPath := c.ScanPaths[0]
	destPath := c.ScanPaths[1]

	var g errgroup.Group
	var src, dest map[string]*malcontent.FileReport
	var srcBase, destBase string
	srcCh := make(chan map[string]*malcontent.FileReport, 1)
	destCh := make(chan map[string]*malcontent.FileReport, 1)
	srcIsArchive := isSupportedArchive(srcPath)
	destIsArchive := isSupportedArchive(destPath)

	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return nil, err
	}

	destInfo, err := os.Stat(destPath)
	if err != nil {
		return nil, err
	}

	g.Go(func() error {
		src, srcBase, err = relFileReport(ctx, c, srcPath)
		if err != nil {
			return err
		}
		srcCh <- src
		return nil
	})

	g.Go(func() error {
		dest, destBase, err = relFileReport(ctx, c, destPath)
		if err != nil {
			return err
		}
		destCh <- dest
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	src = <-srcCh
	dest = <-destCh

	close(srcCh)
	close(destCh)

	d := &malcontent.DiffReport{
		Added:    orderedmap.New[string, *malcontent.FileReport](),
		Removed:  orderedmap.New[string, *malcontent.FileReport](),
		Modified: orderedmap.New[string, *malcontent.FileReport](),
	}

	// When scanning two directories, compare the files in each directory
	// and employ add/delete for files that are not the same
	// When scanning two files, do a 1:1 comparison and
	// consider the source -> destination as a change rather than an add/delete
	if (srcInfo.IsDir() && destInfo.IsDir()) || (srcIsArchive && destIsArchive) {
		handleDir(ctx, c, src, dest, d)
	} else {
		var srcFile, destFile *malcontent.FileReport
		for _, fr := range src {
			srcFile = fr
			break
		}
		for _, fr := range dest {
			destFile = fr
			break
		}
		if srcFile != nil && destFile != nil {
			formatSrc := displayPath(srcBase, srcFile.Path)
			formatDest := displayPath(destBase, destFile.Path)
			if scoreFile(srcFile, destFile) {
				d.Removed.Set(srcFile.Path, srcFile)
				d.Added.Set(destFile.Path, destFile)
				inferMoves(ctx, c, d)
			} else {
				handleFile(ctx, c, srcFile, destFile, fmt.Sprintf("%s -> %s", formatSrc, formatDest), d)
			}
		}
	}

	// skip inferring moves if added and removed are empty
	if d.Added != nil && d.Removed != nil {
		inferMoves(ctx, c, d)
	}
	return &malcontent.Report{Diff: d}, nil
}

func handleDir(ctx context.Context, c malcontent.Config, src, dest map[string]*malcontent.FileReport, d *malcontent.DiffReport) {
	srcFiles := make(map[string]*malcontent.FileReport)
	destFiles := make(map[string]*malcontent.FileReport)

	for path, fr := range src {
		base := filepath.Base(path)
		srcFiles[base] = fr
	}
	for path, fr := range dest {
		base := filepath.Base(path)
		destFiles[base] = fr
	}

	// Check for files that exist in both the source and destination
	// Files that exist in both pass to handleFile which considers files as modifications
	// Otherwise, treat the source file as existing only in the source directory
	// These files are considered removals from the destination
	for name, srcFr := range srcFiles {
		if destFr, exists := destFiles[name]; exists {
			if !filterDiff(ctx, c, srcFr, destFr) {
				formatSrc := displayPath(name, srcFr.Path)
				formatDest := displayPath(name, destFr.Path)
				if scoreFile(srcFr, destFr) {
					d.Removed.Set(srcFr.Path, srcFr)
					d.Added.Set(destFr.Path, destFr)
					inferMoves(ctx, c, d)
				} else {
					handleFile(ctx, c, srcFr, destFr, fmt.Sprintf("%s -> %s", formatSrc, formatDest), d)
				}
			}
		} else {
			formatSrc := displayPath(name, srcFr.Path)
			dirPath := filepath.Dir(formatSrc)
			d.Removed.Set(fmt.Sprintf("%s/%s", dirPath, name), srcFr)
		}
	}

	// Check for files that exist only in the destination directory
	// These files are considered additions to the destination
	for name, destFr := range destFiles {
		if _, exists := srcFiles[name]; !exists {
			formatDest := displayPath(name, destFr.Path)
			dirPath := filepath.Dir(formatDest)
			d.Added.Set(fmt.Sprintf("%s/%s", dirPath, name), destFr)
		}
	}
}

func handleFile(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport, relPath string, d *malcontent.DiffReport) {
	// We've now established that file exists in both source & destination
	if fr.RiskScore < c.MinFileRisk && tr.RiskScore < c.MinFileRisk {
		clog.FromContext(ctx).Info("diff does not meet min trigger level", slog.Any("path", tr.Path))
		return
	}

	// Filter files that are marked for removal
	if filterDiff(ctx, c, fr, tr) {
		return
	}

	rbs := createFileReport(tr, fr)

	// Findings that exist only in the source
	// If true, these are considered to be removed from the destination
	for _, fb := range fr.Behaviors {
		if !behaviorExists(fb, tr.Behaviors) {
			fb.DiffRemoved = true
			rbs.Behaviors = append(rbs.Behaviors, fb)
			continue
		}
	}

	// Findings that exist only in the destination
	// If true, these are considered to be added to the destination
	// If findings exist in both files, then there is no diff for the given behavior
	for _, tb := range tr.Behaviors {
		if !behaviorExists(tb, fr.Behaviors) {
			tb.DiffAdded = true
			rbs.Behaviors = append(rbs.Behaviors, tb)
			continue
		}
		if behaviorExists(tb, fr.Behaviors) {
			rbs.Behaviors = append(rbs.Behaviors, tb)
			continue
		}
	}

	d.Modified.Set(relPath, rbs)
}

func createFileReport(tr, fr *malcontent.FileReport) *malcontent.FileReport {
	return &malcontent.FileReport{
		Path:              tr.Path,
		PreviousPath:      fr.Path,
		PreviousRelPath:   fr.PreviousRelPath,
		Behaviors:         []*malcontent.Behavior{},
		PreviousRiskScore: fr.RiskScore,
		PreviousRiskLevel: fr.RiskLevel,
		RiskLevel:         tr.RiskLevel,
		RiskScore:         tr.RiskScore,
	}
}

func behaviorExists(b *malcontent.Behavior, behaviors []*malcontent.Behavior) bool {
	for _, tb := range behaviors {
		if tb.ID == b.ID {
			return true
		}
	}
	return false
}

// combine iterates over the removed and added channels to create a diff report to store in the combined channel.
func combineReports(removed, added *orderedmap.OrderedMap[string, *malcontent.FileReport]) []malcontent.CombinedReport {
	combined := make([]malcontent.CombinedReport, 0, removed.Len()*added.Len())
	for r := removed.Oldest(); r != nil; r = r.Next() {
		for a := added.Oldest(); a != nil; a = a.Next() {
			score := levenshtein.Match(r.Key, a.Key, levenshtein.NewParams())
			if score < 0.9 {
				continue
			}
			combined = append(combined, malcontent.CombinedReport{
				Added:     a.Key,
				AddedFR:   a.Value,
				Removed:   r.Key,
				RemovedFR: r.Value,
				Score:     score,
			})
		}
	}
	return combined
}

func inferMoves(ctx context.Context, c malcontent.Config, d *malcontent.DiffReport) {
	for _, cr := range combineReports(d.Removed, d.Added) {
		fileMove(ctx, c, cr.RemovedFR, cr.AddedFR, cr.Removed, cr.Added, d, cr.Score)
	}
}

func fileMove(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport, rpath, apath string, d *malcontent.DiffReport, score float64) {
	minRisk := int(math.Min(float64(c.MinRisk), float64(c.MinFileRisk)))
	if fr.RiskScore < minRisk && tr.RiskScore < minRisk {
		clog.FromContext(ctx).Info("diff does not meet min trigger level", slog.Any("path", tr.Path))
		return
	}

	// Filter diffs for files that make it through the combineReports pattern matching
	// i.e., `.so` and `.spdx.json` files
	if filterDiff(ctx, c, fr, tr) {
		return
	}

	// We think that this file moved from rpath to apath.
	abs := &malcontent.FileReport{
		Path:                 tr.Path,
		PreviousPath:         fr.Path,
		PreviousRelPath:      rpath,
		PreviousRelPathScore: score,

		Behaviors:         []*malcontent.Behavior{},
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
		if behaviorExists(fb, tr.Behaviors) {
			abs.Behaviors = append(abs.Behaviors, fb)
		}
	}

	d.Modified.Set(apath, abs)
	d.Removed.Delete(rpath)
	d.Added.Delete(apath)
}

// filterDiff returns a boolean dictating whether a diff report should be ignored depending on the following conditions:
// `true` when passing `--file-risk-change` and the source risk score matches the destination risk score
// `true` when passing `--file-risk-increase` and the source risk score is equal to or greater than the destination risk score
// `false` otherwise.
func filterDiff(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport) bool {
	if c.FileRiskChange && fr.RiskScore == tr.RiskScore {
		clog.FromContext(ctx).Info("dropping result because diff scores were the same", slog.Any("paths", fmt.Sprintf("%s (%d) %s (%d)", fr.Path, fr.RiskScore, tr.Path, tr.RiskScore)))
		return true
	}
	if c.FileRiskIncrease && fr.RiskScore >= tr.RiskScore {
		clog.FromContext(ctx).Info("dropping result because old score was the same or higher than the new score", slog.Any("paths ", fmt.Sprintf("%s (%d) %s (%d)", fr.Path, fr.RiskScore, tr.Path, tr.RiskScore)))
		return true
	}

	return false
}
