// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/agext/levenshtein"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/report"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"golang.org/x/sync/errgroup"
)

type ScanResult struct {
	files    map[string]*malcontent.FileReport
	base     string
	err      error
	tmpRoot  string
	imageURI string
}

// relPath returns the cleanest possible relative path between a source path and files within said path.
func relPath(from string, fr *malcontent.FileReport, isArchive bool, isImage bool) (string, string, error) {
	var (
		base, rel string
		err       error
	)

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
	case isImage:
		from = fr.Path
		if strings.Contains(fr.Path, "∴") {
			parts := strings.Split(fr.Path, "∴")
			if len(parts) > 0 {
				from = strings.TrimSpace(parts[0])
			}
		}
		base, err = filepath.Abs(from)
		if err != nil {
			return "", "", err
		}
		info, err := os.Stat(from)
		if err != nil {
			return "", "", err
		}
		dir := filepath.Dir(from)
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
		rel, err = filepath.Rel(fromRoot, from)
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

// selectPrimaryFile selects a single file from a map of file reports in a deterministic way.
// e.g., when a UPX-packed file is scanned, it produces the decompressed file
// and preserves the original file (with a .~ suffix).
func selectPrimaryFile(files map[string]*malcontent.FileReport) *malcontent.FileReport {
	if len(files) == 0 {
		return nil
	}

	keys := slices.Sorted(maps.Keys(files))

	if i := slices.IndexFunc(keys, func(k string) bool {
		return !strings.HasSuffix(k, ".~")
	}); i >= 0 {
		return files[keys[i]]
	}

	return files[keys[0]]
}

// isUPXBackup returns true if the path is a UPX backup file (.~ suffix)
// and the corresponding decompressed file exists in the files map.
func isUPXBackup(path string, files map[string]*malcontent.FileReport) bool {
	if !strings.HasSuffix(path, ".~") {
		return false
	}

	decompressed := strings.TrimSuffix(path, ".~")
	_, exists := files[decompressed]
	return exists
}

func relFileReport(ctx context.Context, c malcontent.Config, fromPath string, isImage bool) (map[string]*malcontent.FileReport, string, error) {
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}

	fromConfig := c
	fromConfig.Renderer = nil
	fromConfig.ScanPaths = []string{fromPath}
	fromReport, err := recursiveScan(ctx, fromConfig)
	if err != nil {
		return nil, "", err
	}

	fromRelPath := map[string]*malcontent.FileReport{}

	var (
		base     string
		rangeErr error
	)

	fromReport.Files.Range(func(key, value any) bool {
		if ctx.Err() != nil {
			return false
		}
		if key == nil || value == nil {
			return true
		}

		if fr, ok := value.(*malcontent.FileReport); ok {
			isArchive := fr.ArchiveRoot != ""
			if fr.Skipped != "" {
				return true
			}

			rel, b, err := relPath(fromPath, fr, isArchive, isImage)
			if err != nil {
				rangeErr = err
				return false
			}

			fr.PreviousRelPath = rel
			fromRelPath[rel] = fr
			base = b
		}
		return true
	})

	if rangeErr != nil {
		return nil, "", rangeErr
	}

	return fromRelPath, base, nil
}

// scoreFile returns a boolean to determine how individual files are stored in a diff report.
func scoreFile(fr, tr *malcontent.FileReport) bool {
	patterns := []string{
		`^(.+)\/([^\/]+)\.so(\..*)?$`,
		`^(.+)\/([^\/]+).spdx\.json$`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)

		// If both files match patterns, return true to indicate that `inferMoves` should be used
		// Otherwise, indicate that `handleFile` should be used
		if re.MatchString(fr.Path) && re.MatchString(tr.Path) {
			return true
		}
	}

	return false
}

func Diff(ctx context.Context, c malcontent.Config, _ *clog.Logger) (*malcontent.Report, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if len(c.ScanPaths) != 2 {
		return nil, fmt.Errorf("diff mode requires 2 paths, you passed in %d path(s)", len(c.ScanPaths))
	}

	srcPath, destPath := c.ScanPaths[0], c.ScanPaths[1]

	// If diffing images, use their temporary directories as scan paths
	// Flip c.OCI to false when finished to block other image code paths
	var (
		err      error
		isImage  bool
		isReport bool
	)

	if c.OCI {
		srcPath, err = archive.OCI(ctx, srcPath)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare scan path: %w", err)
		}
		destPath, err = archive.OCI(ctx, destPath)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare scan path: %w", err)
		}
		isImage, c.OCI = true, false
	}

	srcCh, destCh := make(chan ScanResult, 1), make(chan ScanResult, 1)
	srcIsArchive, destIsArchive := programkind.IsSupportedArchive(ctx, srcPath), programkind.IsSupportedArchive(ctx, destPath)
	srcResult, destResult := ScanResult{}, ScanResult{}

	// If diffing existing reports, we just need to unmarshal them into a ScanResult and run the diff
	// Only JSON or YAML reports are supported, however
	switch c.Report {
	case true:
		isReport = true
		srcFile, err := os.Open(srcPath)
		if err != nil {
			return nil, err
		}
		defer srcFile.Close()
		src, err := io.ReadAll(srcFile)
		if err != nil {
			return nil, err
		}
		srcFiles, err := report.Load(src)
		srcResult.err = err
		srcResult.files = srcFiles.FileReports

		// Extract image URI and temp root from the report's file paths
		srcResult.imageURI = report.ExtractImageURI(srcResult.files)
		srcResult.tmpRoot = report.ExtractTmpRoot(srcResult.files)
		srcResult.base = filepath.Base(srcPath)

		destFile, err := os.Open(destPath)
		if err != nil {
			return nil, err
		}
		defer destFile.Close()
		dst, err := io.ReadAll(destFile)
		if err != nil {
			return nil, err
		}

		destFiles, err := report.Load(dst)
		destResult.err = err
		destResult.files = destFiles.FileReports

		// Extract image URI and temp root from the report's file paths
		destResult.imageURI = report.ExtractImageURI(destResult.files)
		destResult.tmpRoot = report.ExtractTmpRoot(destResult.files)
	default:
		var g errgroup.Group

		g.Go(func() error {
			files, base, err := relFileReport(ctx, c, srcPath, isImage)
			res := ScanResult{files: files, base: base, err: err}
			if isImage {
				res.imageURI, res.tmpRoot = c.ScanPaths[0], srcPath
			}
			srcCh <- res
			return err
		})

		srcResult = <-srcCh
		if srcResult.err != nil {
			return nil, fmt.Errorf("source scan error: %w", srcResult.err)
		}

		g.Go(func() error {
			files, base, err := relFileReport(ctx, c, destPath, isImage)
			res := ScanResult{files: files, base: base, err: err}
			if isImage {
				res.imageURI, res.tmpRoot = c.ScanPaths[1], destPath
			}
			destCh <- res
			return err
		})

		destResult = <-destCh
		if destResult.err != nil {
			return nil, fmt.Errorf("destination scan error: %w", destResult.err)
		}

		if err := g.Wait(); err != nil {
			return nil, err
		}
	}

	d := &malcontent.DiffReport{
		Added:    orderedmap.New[string, *malcontent.FileReport](),
		Removed:  orderedmap.New[string, *malcontent.FileReport](),
		Modified: orderedmap.New[string, *malcontent.FileReport](),
	}

	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return nil, err
	}

	destInfo, err := os.Stat(destPath)
	if err != nil {
		return nil, err
	}

	// When scanning two directories, compare the files in each directory
	// and employ add/delete for files that are not the same
	// When scanning two files, do a 1:1 comparison and
	// consider the source -> destination as a change rather than an add/delete
	shouldHandleDir := ((srcInfo.IsDir() && destInfo.IsDir()) || (srcIsArchive && destIsArchive)) || isImage || isReport
	archiveOrImage := (srcIsArchive && destIsArchive) || isImage

	if shouldHandleDir {
		handleDir(ctx, c, srcResult, destResult, d, archiveOrImage, isReport)
	} else {
		srcFile := selectPrimaryFile(srcResult.files)
		destFile := selectPrimaryFile(destResult.files)
		if srcFile != nil && destFile != nil {
			removed := formatKey(srcResult, CleanPath(srcFile.Path, srcResult.tmpRoot))
			added := formatKey(srcResult, CleanPath(destFile.Path, destResult.tmpRoot))
			if c.ScoreAll || scoreFile(srcFile, destFile) {
				d.Removed.Set(removed, srcFile)
				d.Added.Set(added, destFile)
			} else {
				handleFile(ctx, c, srcFile, destFile, removed, added, d, srcResult, destResult, archiveOrImage, isReport)
			}
		}
	}

	// infer moves only if there are entries in both Added and Removed
	if d.Added.Len() > 0 && d.Removed.Len() > 0 {
		inferMoves(ctx, c, d, srcResult, destResult, archiveOrImage, isReport)
	}

	defer func() {
		close(srcCh)
		close(destCh)
	}()

	return &malcontent.Report{Diff: d}, nil
}

func handleDir(ctx context.Context, c malcontent.Config, src, dest ScanResult, d *malcontent.DiffReport, archiveOrImage, isReport bool) {
	if ctx.Err() != nil {
		return
	}

	srcFiles, destFiles := make(map[string]*malcontent.FileReport), make(map[string]*malcontent.FileReport)

	for rel, fr := range src.files {
		if rel != "" && !isUPXBackup(rel, src.files) {
			srcFiles[rel] = fr
		}
	}
	for rel, fr := range dest.files {
		if rel != "" && !isUPXBackup(rel, dest.files) {
			destFiles[rel] = fr
		}
	}

	// sort keys for deterministic iteration order
	srcKeys := make([]string, 0, len(srcFiles))
	for k := range srcFiles {
		srcKeys = append(srcKeys, k)
	}
	slices.Sort(srcKeys)

	destKeys := make([]string, 0, len(destFiles))
	for k := range destFiles {
		destKeys = append(destKeys, k)
	}
	slices.Sort(destKeys)

	// Check for files that exist in both the source and destination
	// Files that exist in both pass to handleFile which considers files as modifications
	// Otherwise, treat the source file as existing only in the source directory
	// These files are considered removals from the destination
	for _, name := range srcKeys {
		srcFr := srcFiles[name]
		var removed string
		if isReport {
			removed = report.FormatReportKey(srcFr.Path, src.tmpRoot, src.imageURI)
		} else {
			removed = formatKey(src, CleanPath(srcFr.Path, src.tmpRoot))
		}
		if destFr, exists := destFiles[name]; exists {
			var added string
			if isReport {
				added = report.FormatReportKey(destFr.Path, dest.tmpRoot, dest.imageURI)
			} else {
				added = formatKey(dest, CleanPath(destFr.Path, dest.tmpRoot))
			}
			if filterDiff(ctx, c, srcFr, destFr) {
				continue
			}
			if c.ScoreAll || scoreFile(srcFr, destFr) {
				d.Removed.Set(removed, srcFr)
				d.Added.Set(added, destFr)
			} else {
				handleFile(ctx, c, srcFr, destFr, removed, added, d, src, dest, archiveOrImage, isReport)
			}
		} else {
			d.Removed.Set(removed, srcFr)
		}
	}

	// Check for files that exist only in the destination directory
	// These files are considered additions to the destination
	for _, name := range destKeys {
		destFr := destFiles[name]
		var added string
		if isReport {
			added = report.FormatReportKey(destFr.Path, dest.tmpRoot, dest.imageURI)
		} else {
			added = formatKey(dest, CleanPath(destFr.Path, dest.tmpRoot))
		}
		if _, exists := srcFiles[name]; !exists {
			d.Added.Set(added, destFr)
		}
	}
}

func handleFile(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport, removed, added string, d *malcontent.DiffReport, _, dest ScanResult, archiveOrImage, isReport bool) {
	if ctx.Err() != nil {
		return
	}

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
		}
		rbs.Behaviors = append(rbs.Behaviors, fb)
	}

	// Findings that exist only in the destination
	// If true, these are considered to be added to the destination
	// If findings exist in both files, then there is no diff for the given behavior
	for _, tb := range tr.Behaviors {
		if !behaviorExists(tb, fr.Behaviors) {
			tb.DiffAdded = true
		}
		rbs.Behaviors = append(rbs.Behaviors, tb)
	}

	// Sort behaviors by ID for deterministic output
	sort.Slice(rbs.Behaviors, func(i, j int) bool {
		return rbs.Behaviors[i].ID < rbs.Behaviors[j].ID
	})

	if isReport {
		rbs.Path = report.FormatReportKey(rbs.Path, dest.tmpRoot, dest.imageURI)
	} else if archiveOrImage {
		rbs.Path = CleanPath(rbs.Path, "/private")
		rbs.Path = formatKey(dest, CleanPath(rbs.Path, dest.tmpRoot))
	}
	relPath := fmt.Sprintf("%s -> %s", removed, added)

	d.Modified.Set(relPath, rbs)
	d.Removed.Delete(removed)
	d.Added.Delete(added)
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
		if b.ID == tb.ID {
			return true
		}
	}
	return false
}

// combineReports performs one-to-one matching between removed and added files.
// all Levenshtein scores are calculated and then files are paired by highest score,
// ensuring each removed file matches at most one added file.
func combineReports(ctx context.Context, c malcontent.Config, removed, added *orderedmap.OrderedMap[string, *malcontent.FileReport]) []malcontent.CombinedReport {
	if ctx.Err() != nil {
		return nil
	}

	type scoredPair struct {
		rpath string
		rfr   *malcontent.FileReport
		apath string
		afr   *malcontent.FileReport
		score float64
	}

	allPairs := make([]scoredPair, 0, removed.Len()*added.Len())
	for r := removed.Oldest(); r != nil; r = r.Next() {
		for a := added.Oldest(); a != nil; a = a.Next() {
			// when not using ScoreAll, only compute distances for files matching scoreFile patterns
			if !c.ScoreAll && !scoreFile(r.Value, a.Value) {
				continue
			}
			// avoid the CPU cycles involved in scoring files with identical names
			// since the score would be 1.0 indicating a perfect match
			var score float64
			if filepath.Base(r.Key) == filepath.Base(a.Key) {
				score = 1.0
			} else {
				score = levenshtein.Match(filepath.Base(r.Key), filepath.Base(a.Key), levenshtein.NewParams())
			}
			allPairs = append(allPairs, scoredPair{
				rpath: r.Key,
				rfr:   r.Value,
				apath: a.Key,
				afr:   a.Value,
				score: score,
			})
		}
	}

	// sort pairs by score descending, then by path for deterministic ordering
	slices.SortFunc(allPairs, func(a, b scoredPair) int {
		if a.score != b.score {
			if a.score > b.score {
				return -1
			}
			return 1
		}
		// for equal scores, sort by removed path, then added path
		if a.rpath != b.rpath {
			if a.rpath < b.rpath {
				return -1
			}
			return 1
		}
		if a.apath < b.apath {
			return -1
		}
		if a.apath > b.apath {
			return 1
		}
		return 0
	})

	// once a removed or added file is used, don't use reuse it
	usedRemoved := make(map[string]bool)
	usedAdded := make(map[string]bool)
	combined := make([]malcontent.CombinedReport, 0, min(removed.Len(), added.Len()))

	for _, pair := range allPairs {
		if usedRemoved[pair.rpath] || usedAdded[pair.apath] {
			continue
		}
		usedRemoved[pair.rpath] = true
		usedAdded[pair.apath] = true
		combined = append(combined, malcontent.CombinedReport{
			Added:     pair.apath,
			AddedFR:   pair.afr,
			Removed:   pair.rpath,
			RemovedFR: pair.rfr,
			Score:     pair.score,
		})
	}

	return combined
}

func inferMoves(ctx context.Context, c malcontent.Config, d *malcontent.DiffReport, src, dest ScanResult, archiveOrImage, isReport bool) {
	if ctx.Err() != nil {
		return
	}

	for _, cr := range combineReports(ctx, c, d.Removed, d.Added) {
		fileMove(ctx, c, cr.RemovedFR, cr.AddedFR, cr.Removed, cr.Added, d, cr.Score, src, dest, archiveOrImage, isReport)
	}
}

func fileMove(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport, rpath, apath string, d *malcontent.DiffReport, score float64, src ScanResult, dest ScanResult, archiveOrImage, isReport bool) {
	if ctx.Err() != nil {
		return
	}

	minRisk := min(c.MinRisk, c.MinFileRisk)
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
		PreviousRelPath:      fr.PreviousRelPath,
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
	}

	// Sort behaviors by ID for deterministic output
	sort.Slice(abs.Behaviors, func(i, j int) bool {
		return abs.Behaviors[i].ID < abs.Behaviors[j].ID
	})

	if isReport {
		abs.Path = report.FormatReportKey(abs.Path, dest.tmpRoot, dest.imageURI)
		abs.PreviousPath = report.FormatReportKey(abs.PreviousPath, src.tmpRoot, src.imageURI)
	} else if archiveOrImage {
		abs.Path = CleanPath(abs.Path, "/private")
		abs.PreviousPath = CleanPath(abs.PreviousPath, "/private")
		abs.Path = formatKey(dest, CleanPath(abs.Path, dest.tmpRoot))
		abs.PreviousPath = formatKey(src, CleanPath(abs.PreviousPath, src.tmpRoot))
	}

	d.Removed.Delete(rpath)
	d.Added.Delete(apath)
	d.Modified.Set(apath, abs)
}

// filterDiff returns a boolean dictating whether a diff report should be ignored depending on the following conditions:
// `true` when passing `--file-risk-change` and the source risk score matches the destination risk score
// `true` when passing `--file-risk-increase` and the source risk score is equal to or greater than the destination risk score
// `false` otherwise.
func filterDiff(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport) bool {
	if ctx.Err() != nil {
		return false
	}

	switch {
	case c.FileRiskChange && fr.RiskScore == tr.RiskScore:
		clog.FromContext(ctx).Info("dropping result because diff scores were the same", slog.Any("paths", fmt.Sprintf("%s (%d) %s (%d)", fr.Path, fr.RiskScore, tr.Path, tr.RiskScore)))
		return true
	case c.FileRiskIncrease && fr.RiskScore >= tr.RiskScore:
		clog.FromContext(ctx).Info("dropping result because old score was the same or higher than the new score", slog.Any("paths ", fmt.Sprintf("%s (%d) %s (%d)", fr.Path, fr.RiskScore, tr.Path, tr.RiskScore)))
		return true
	default:
		return false
	}
}

// formatKey takes a scan result and a file name to construct a well-known map key.
func formatKey(res ScanResult, name string) string {
	switch {
	case res.imageURI != "":
		return fmt.Sprintf("%s ∴ %s", res.imageURI, name)
	case res.tmpRoot != "":
		return fmt.Sprintf("%s ∴ %s", res.tmpRoot, name)
	case res.base != "":
		return fmt.Sprintf("%s ∴ %s", res.base, name)
	default:
		return name
	}
}
