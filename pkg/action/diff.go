// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/egibs/reconcile/pkg/files"
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
func selectPrimaryFile(f map[string]*malcontent.FileReport) *malcontent.FileReport {
	if len(f) == 0 {
		return nil
	}

	keys := slices.Sorted(maps.Keys(f))

	if i := slices.IndexFunc(keys, func(k string) bool {
		return !strings.HasSuffix(k, ".~")
	}); i >= 0 {
		return f[keys[i]]
	}

	return f[keys[0]]
}

// isUPXBackup returns true if the path is a UPX backup file (.~ suffix)
// and the corresponding decompressed file exists in the files map.
func isUPXBackup(path string, f map[string]*malcontent.FileReport) bool {
	if !strings.HasSuffix(path, ".~") {
		return false
	}

	decompressed := strings.TrimSuffix(path, ".~")
	_, exists := f[decompressed]
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
		srcPath, err = archive.OCI(ctx, srcPath, c.OCIAuth, c.MaxImageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare scan path: %w", err)
		}
		destPath, err = archive.OCI(ctx, destPath, c.OCIAuth, c.MaxImageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare scan path: %w", err)
		}
		isImage, c.OCI = true, false
	}

	srcCh, destCh := make(chan ScanResult, 1), make(chan ScanResult, 1)

	defer func() {
		close(srcCh)
		close(destCh)
	}()

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

		st, err := srcFile.Stat()
		if err != nil {
			return nil, err
		}

		// create a buffer sized to the minimum of the file's size or the default ReadBuffer
		// only do so if we actually need to retrieve the file's contents
		buf := readPool.Get(min(st.Size(), file.ReadBuffer)) //nolint:nilaway // the buffer pool is created above

		src, err := file.GetContents(srcFile, buf)
		if err != nil {
			return nil, err
		}
		readPool.Put(buf)

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

		st, err = destFile.Stat()
		if err != nil {
			return nil, err
		}

		// create a buffer sized to the minimum of the file's size or the default ReadBuffer
		// only do so if we actually need to retrieve the file's contents
		buf = readPool.Get(min(st.Size(), file.ReadBuffer)) //nolint:nilaway // the buffer pool is created above

		dst, err := file.GetContents(destFile, buf)
		if err != nil {
			return nil, err
		}
		readPool.Put(buf)

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
			added := formatKey(destResult, CleanPath(destFile.Path, destResult.tmpRoot))
			fileDiff(ctx, c, srcFile, destFile, removed, added, d, srcResult, destResult, archiveOrImage, isReport, false)
		}
	}

	return &malcontent.Report{Diff: d}, nil
}

// handleDir uses diff for O(n+m) file reconciliation with identity-based matching.
// This enables detection of version updates (e.g., lib.so.1 -> lib.so.2) in addition
// to exact path matches, and scales efficiently to millions of files.
func handleDir(ctx context.Context, c malcontent.Config, src, dest ScanResult, d *malcontent.DiffReport, archiveOrImage, isReport bool) {
	if ctx.Err() != nil {
		return
	}

	// Build file maps keyed by relative path (i.e., the path within an image/archive, not the temp dir)
	// This ensures files with the same logical path match regardless of temporary directory.
	srcFiles := make(map[string]*malcontent.FileReport)
	destFiles := make(map[string]*malcontent.FileReport)
	var srcPaths, destPaths []string

	for rel, fr := range src.files {
		if rel == "" || isUPXBackup(rel, src.files) {
			continue
		}
		relPath := extractPath(rel, fr, src, archiveOrImage, isReport)
		if relPath != "" {
			srcFiles[relPath] = fr
			srcPaths = append(srcPaths, relPath)
		}
	}
	for rel, fr := range dest.files {
		if rel == "" || isUPXBackup(rel, dest.files) {
			continue
		}
		relPath := extractPath(rel, fr, dest, archiveOrImage, isReport)
		if relPath != "" {
			destFiles[relPath] = fr
			destPaths = append(destPaths, relPath)
		}
	}

	// Sort paths for deterministic ordering
	slices.Sort(srcPaths)
	slices.Sort(destPaths)

	// Fast O(n+m) reconciliation with identity-based matching
	result := files.Diff(srcPaths, destPaths)

	// Collect all entries for deterministic sorting
	// The reconcile package uses concurrency, so initial order is non-deterministic
	type diffEntry struct {
		status   files.Status
		entry    files.Entry
		sortKey  string
		srcPath  string
		destPath string
	}

	entries := make([]diffEntry, 0, len(result.E))
	for status, entry := range result.All() {
		var sortKey, srcPath, destPath string
		switch status {
		case files.Unchanged, files.Updated:
			srcPath = srcPaths[entry.Old]
			destPath = destPaths[entry.New]
			sortKey = destPath
		case files.Removed:
			srcPath = srcPaths[entry.Old]
			sortKey = srcPath
		case files.Added:
			destPath = destPaths[entry.New]
			sortKey = destPath
		}
		entries = append(entries, diffEntry{status, entry, sortKey, srcPath, destPath})
	}

	// Sort entries by path for deterministic output
	slices.SortFunc(entries, func(a, b diffEntry) int {
		return strings.Compare(a.sortKey, b.sortKey)
	})

	for _, e := range entries {
		switch e.status {
		case files.Unchanged, files.Updated:
			srcFr := srcFiles[e.srcPath]
			destFr := destFiles[e.destPath]

			if filterDiff(ctx, c, srcFr, destFr) {
				continue
			}

			rpath := formatReportKey(src, srcFr, isReport)
			apath := formatReportKey(dest, destFr, isReport)
			// Determine whether this is a move (Updated) vs change (Unchanged)
			isMoved := e.status == files.Updated
			fileDiff(ctx, c, srcFr, destFr, rpath, apath, d, src, dest, archiveOrImage, isReport, isMoved)

		case files.Removed:
			srcFr := srcFiles[e.srcPath]
			removed := formatReportKey(src, srcFr, isReport)
			d.Removed.Set(removed, srcFr)

		case files.Added:
			destFr := destFiles[e.destPath]
			added := formatReportKey(dest, destFr, isReport)
			d.Added.Set(added, destFr)
		}
	}
}

// extractPath returns a clean, relative path for reconciliation.
// For archives/images: trims the temporary directory root and returns the path within an archive/image.
// For reports: extracts path after ∴ separator, or trims temporary directory patterns.
// For regular files: returns the relative path unchanged.
func extractPath(rel string, fr *malcontent.FileReport, res ScanResult, archiveOrImage, isReport bool) string {
	switch {
	case isReport:
		// For reports, paths may be formatted as "imageURI ∴ /path" or raw temp paths
		path := fr.Path
		if strings.Contains(path, "∴") {
			// Extract just the file path after the separator
			parts := strings.SplitN(path, "∴", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[len(parts)-1])
			}
		}
		// Fall back to cleaning temp root if present
		return report.CleanReportPath(path, res.tmpRoot, "")
	case archiveOrImage && res.tmpRoot != "":
		// Strip temp root to get canonical path within archive/image
		return CleanPath(fr.Path, res.tmpRoot)
	default:
		return rel
	}
}

// formatReportKey returns a formatted key for diff report entries.
func formatReportKey(res ScanResult, fr *malcontent.FileReport, isReport bool) string {
	if isReport {
		return report.FormatReportKey(fr.Path, res.tmpRoot, res.imageURI)
	}
	return formatKey(res, CleanPath(fr.Path, res.tmpRoot))
}

// fileDiff handles files that exist in both source and destination.
func fileDiff(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport, rpath, apath string, d *malcontent.DiffReport, src ScanResult, dest ScanResult, archiveOrImage, isReport, isMoved bool) {
	if ctx.Err() != nil {
		return
	}

	if fr.RiskScore < c.MinFileRisk && tr.RiskScore < c.MinFileRisk {
		clog.FromContext(ctx).Info("diff does not meet min trigger level", slog.Any("path", tr.Path))
		return
	}

	// Filter diffs for files that make it through the combineReports pattern matching
	// i.e., `.so` and `.spdx.json` files
	if filterDiff(ctx, c, fr, tr) {
		return
	}

	abs := &malcontent.FileReport{
		Path:            tr.Path,
		PreviousRelPath: fr.PreviousRelPath,

		Behaviors:         []*malcontent.Behavior{},
		PreviousRiskScore: fr.RiskScore,
		PreviousRiskLevel: fr.RiskLevel,

		RiskScore: tr.RiskScore,
		RiskLevel: tr.RiskLevel,
	}

	// Only set PreviousPath for moved files (version updates/renames)
	// Changed files (same name) don't need PreviousPath
	if isMoved {
		abs.PreviousPath = fr.Path
	}

	srcBehaviorIDs := make(map[string]struct{}, len(fr.Behaviors))
	for _, b := range fr.Behaviors {
		srcBehaviorIDs[b.ID] = struct{}{}
	}
	destBehaviorIDs := make(map[string]struct{}, len(tr.Behaviors))
	for _, b := range tr.Behaviors {
		destBehaviorIDs[b.ID] = struct{}{}
	}

	// if destination behavior is not in the source
	for _, tb := range tr.Behaviors {
		if _, ok := srcBehaviorIDs[tb.ID]; !ok {
			tb.DiffAdded = true
			abs.Behaviors = append(abs.Behaviors, tb)
		}
	}

	// if source behavior is not in the destination
	for _, fb := range fr.Behaviors {
		if _, ok := destBehaviorIDs[fb.ID]; !ok {
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
		if isMoved {
			abs.PreviousPath = report.FormatReportKey(abs.PreviousPath, src.tmpRoot, src.imageURI)
		}
	} else if archiveOrImage {
		abs.Path = CleanPath(abs.Path, "/private")
		abs.Path = formatKey(dest, CleanPath(abs.Path, dest.tmpRoot))
		if isMoved {
			abs.PreviousPath = CleanPath(abs.PreviousPath, "/private")
			abs.PreviousPath = formatKey(src, CleanPath(abs.PreviousPath, src.tmpRoot))
		}
	}

	d.Removed.Delete(rpath)
	d.Added.Delete(apath)
	d.Modified.Set(apath, abs)
}

// behavior represents the parsed components of a behavior ID.
// e.g., "anti-static/base64/eval" -> objective="anti-static", resource="base64", technique="eval".
type behavior struct {
	objective string
	resource  string
	technique string
}

// Sensitivity levels:
// 1: Only display a diff if the file's risk score changes (equivalent to FileRiskChange)
// 2: Only display a diff if the file's objective changes (e.g., anti-static -> c2)
// 3: Only display a diff if the file's resource changes (e.g., base64 -> binary)
// 4: Only display a diff if the file's technique changes (e.g., eval -> exec)
// 5: Display all files in a diff (default, no filtering)
const (
	CHANGE = iota + 1
	OBJECTIVE
	RESOURCE
	TECHNIQUE
	ALL
)

// parseBehaviorID parses a behavior ID into its component parts.
func parseBehaviorID(id string) behavior {
	parts := strings.Split(id, "/")
	bc := behavior{}

	switch len(parts) {
	case 1:
		bc.objective = parts[0]
	case 2:
		bc.objective = parts[0]
		bc.resource = parts[1]
	default:
		if len(parts) >= 3 {
			bc.objective = parts[0]
			bc.resource = parts[1]
			bc.technique = strings.Join(parts[2:], "/")
		}
	}

	return bc
}

// extractBehaviors extracts unique components at the specified sensitivity level from behaviors.
func extractBehaviors(behaviors []*malcontent.Behavior, sensitivity int) map[string]bool {
	components := make(map[string]bool)

	for _, b := range behaviors {
		if b == nil {
			continue
		}

		bc := parseBehaviorID(b.ID)

		switch sensitivity {
		case OBJECTIVE:
			if bc.objective != "" {
				components[bc.objective] = true
			}
		case RESOURCE:
			if bc.objective != "" && bc.resource != "" {
				key := fmt.Sprintf("%s/%s", bc.objective, bc.resource)
				components[key] = true
			} else if bc.objective != "" {
				components[bc.objective] = true
			}
		case TECHNIQUE:
			if b.ID != "" {
				components[b.ID] = true
			}
		}
	}

	return components
}

// behaviorsChanged checks if there are any differences between source and destination behaviors at the specified sensitivity level.
func behaviorsChanged(fr, tr *malcontent.FileReport, sensitivity int) bool {
	sb := extractBehaviors(fr.Behaviors, sensitivity)
	db := extractBehaviors(tr.Behaviors, sensitivity)

	for bc := range db {
		if !sb[bc] {
			return true
		}
	}

	for bc := range sb {
		if !db[bc] {
			return true
		}
	}

	return false
}

// filterDiff returns a boolean dictating whether a diff report should be ignored depending on the following conditions:
// `true` when passing `--file-risk-change` or --sensitivity=1 and the source risk score matches the destination risk score
// `true` when passing `--file-risk-increase` and the source risk score is equal to or greater than the destination risk score
// `true` when passing --sensitivity=2/3/4 and no changes at the corresponding level (objective/resource/technique)
// `false` otherwise.
func filterDiff(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport) bool {
	if ctx.Err() != nil {
		return false
	}

	var (
		change    = c.FileRiskChange || c.Sensitivity == CHANGE
		equalRisk = fr.RiskScore == tr.RiskScore
		lessRisk  = fr.RiskScore >= tr.RiskScore
	)

	switch {
	case c.Sensitivity == ALL:
		return false
	case c.Sensitivity == TECHNIQUE:
		if !behaviorsChanged(fr, tr, TECHNIQUE) {
			clog.FromContext(ctx).Info("dropping result because no technique-level changes detected",
				slog.Any("paths", fmt.Sprintf("%s -> %s", fr.Path, tr.Path)))
			return true
		}
		return false
	case c.Sensitivity == RESOURCE:
		if !behaviorsChanged(fr, tr, RESOURCE) {
			clog.FromContext(ctx).Info("dropping result because no resource-level changes detected",
				slog.Any("paths", fmt.Sprintf("%s -> %s", fr.Path, tr.Path)))
			return true
		}
		return false
	case c.Sensitivity == OBJECTIVE:
		if !behaviorsChanged(fr, tr, OBJECTIVE) {
			clog.FromContext(ctx).Info("dropping result because no objective-level changes detected",
				slog.Any("paths", fmt.Sprintf("%s -> %s", fr.Path, tr.Path)))
			return true
		}
		return false
	case change && equalRisk:
		clog.FromContext(ctx).Info("dropping result because diff scores were the same",
			slog.Any("paths", fmt.Sprintf("%s (%d) %s (%d)", fr.Path, fr.RiskScore, tr.Path, tr.RiskScore)))
		return true
	case c.FileRiskIncrease && lessRisk:
		clog.FromContext(ctx).Info("dropping result because old score was the same or higher than the new score",
			slog.Any("paths ", fmt.Sprintf("%s (%d) %s (%d)", fr.Path, fr.RiskScore, tr.Path, tr.RiskScore)))
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
	case res.base != "":
		return fmt.Sprintf("%s ∴ %s", res.base, name)
	default:
		return name
	}
}
