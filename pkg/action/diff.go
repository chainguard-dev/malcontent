// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/egibs/reconcile/pkg/files"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

type ScanResult struct {
	files    map[string]*malcontent.FileReport
	base     string
	tmpRoot  string
	imageURI string
	// isArchive is set when the scan path is itself an archive, whose entries
	// are keyed by their path within it.
	isArchive bool
}

// relPath returns the key that pairs fr with its counterpart in the other scan,
// and the base that prefixes its report key. Entries of an archive scan are keyed
// by their path within the archive; other files by their path below the scan root.
func relPath(from string, fr *malcontent.FileReport, isArchive bool) (string, string, error) {
	base, err := filepath.Abs(from)
	if err != nil {
		return "", "", err
	}
	if isArchive {
		return archiveEntryPath(fr), base, nil
	}

	info, err := file.Stat(from)
	if err != nil {
		return "", "", err
	}
	// Remove any file name so a single file is keyed by its name: keying
	// both sides as "." would pair completely unrelated files and paths.
	root := from
	if !info.IsDir() {
		root = filepath.Dir(from)
	}
	fromRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", err
	}
	target := fr.Path
	if !pathWithin(target, fromRoot) {
		// The path is spelled through a symlinked directory (e.g. macOS' /tmp -> /private/tmp),
		// so resolve both sides the same way before comparing them.
		fromRoot, target = resolvePath(fromRoot), resolvePath(target)
	}
	rel, err := filepath.Rel(fromRoot, target)
	if err != nil {
		return "", "", err
	}
	return rel, base, nil
}

// archiveEntryPath returns the path of fr within its archive, with a leading slash.
// It depends only on where the entry sits below its own extraction root, so the
// same entry yields the same path in every scan.
func archiveEntryPath(fr *malcontent.FileReport) string {
	if fr.ArchiveRoot != "" && fr.FullPath != "" {
		root, full := fr.ArchiveRoot, fr.FullPath
		if !pathWithin(full, root) {
			root, full = resolvePath(root), resolvePath(full)
		}
		if rel, err := filepath.Rel(root, full); err == nil && filepath.IsLocal(rel) {
			return "/" + filepath.ToSlash(rel)
		}
	}
	// Entries without behaviors carry only their display path: "<archive> ∴ <entry>".
	if _, entry, ok := strings.Cut(fr.Path, " ∴ "); ok {
		return entry
	}
	return fr.Path
}

// pathWithin reports whether p is root or lies below it, comparing the paths as written.
func pathWithin(p, root string) bool {
	if root == "." {
		return filepath.IsLocal(p)
	}
	rest, ok := strings.CutPrefix(p, root)
	if !ok {
		return false
	}
	sep := string(filepath.Separator)
	return rest == "" || strings.HasPrefix(rest, sep) || strings.HasSuffix(root, sep)
}

// resolvePath returns the absolute form of p with symlinks resolved in its longest
// existing prefix, so paths below a removed temporary directory resolve consistently.
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	for dir := abs; ; dir = filepath.Dir(dir) {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(resolved, abs[len(dir):])
		}
		if filepath.Dir(dir) == dir {
			return abs
		}
	}
}

// selectPrimaryFile selects a single file from a map of file reports in a deterministic way.
// e.g., when a UPX-packed file is scanned, it produces the decompressed file
// and preserves the original file (with a .~ suffix).
func selectPrimaryFile(f map[string]*malcontent.FileReport) *malcontent.FileReport {
	if len(f) == 0 {
		return nil
	}

	keys := slices.Sorted(maps.Keys(f))
	for _, k := range keys {
		if !strings.HasSuffix(k, ".~") {
			return f[k]
		}
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

// relFileReport scans fromPath and keys each file report by relPath.
// isArchive reports whether fromPath is itself an archive.
func relFileReport(ctx context.Context, c malcontent.Config, fromPath string, isArchive bool) (map[string]*malcontent.FileReport, string, error) {
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

	fromReport.Files.Range(func(key string, fr *malcontent.FileReport) bool {
		if ctx.Err() != nil {
			return false
		}
		if key == "" || fr == nil {
			return true
		}

		if fr.Skipped != "" {
			return true
		}

		rel, b, err := relPath(fromPath, fr, isArchive)
		if err != nil {
			rangeErr = err
			return false
		}

		fr.PreviousRelPath = rel
		fromRelPath[rel] = fr
		base = b

		return true
	})

	if rangeErr != nil {
		return nil, "", rangeErr
	}
	// Range stops early once ctx is canceled, leaving the map incomplete.
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	return fromRelPath, base, nil
}

func Diff(ctx context.Context, c malcontent.Config, _ *clog.Logger) (*malcontent.Report, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	ctx = malcontent.ContextWithConfig(ctx, &c)

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
		// Scanning with c.OCI unset skips the scanner's own cleanup of extracted images.
		logger := clog.FromContext(ctx)
		srcPath, err = archive.OCIWithConfig(ctx, srcPath, &c)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare scan path: %w", err)
		}
		defer cleanupOCIPath(srcPath, logger)
		destPath, err = archive.OCIWithConfig(ctx, destPath, &c)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare scan path: %w", err)
		}
		defer cleanupOCIPath(destPath, logger)
		isImage, c.OCI = true, false
	}

	srcIsArchive, destIsArchive := programkind.IsSupportedArchive(ctx, srcPath), programkind.IsSupportedArchive(ctx, destPath)
	srcResult, destResult := ScanResult{}, ScanResult{}

	// If diffing existing reports, we just need to unmarshal them into a ScanResult and run the diff
	// Only JSON or YAML reports are supported, however
	switch c.Report {
	case true:
		isReport = true
		srcFile, err := file.Open(srcPath)
		if err != nil {
			return nil, err
		}
		defer srcFile.Close()

		src, err := file.GetContents(srcFile)
		if err != nil {
			return nil, err
		}

		srcFiles, err := report.Load(src)
		if err != nil {
			return nil, fmt.Errorf("load source report: %w", err)
		}
		srcResult.files = srcFiles.FileReports

		// Extract image URI and temp root from the report's file paths
		srcResult.imageURI = report.ExtractImageURI(srcResult.files)
		srcResult.tmpRoot = report.ExtractTmpRoot(srcResult.files)

		destFile, err := file.Open(destPath)
		if err != nil {
			return nil, err
		}
		defer destFile.Close()

		dst, err := file.GetContents(destFile)
		if err != nil {
			return nil, err
		}

		destFiles, err := report.Load(dst)
		if err != nil {
			return nil, fmt.Errorf("load destination report: %w", err)
		}
		destResult.files = destFiles.FileReports

		// Extract image URI and temp root from the report's file paths
		destResult.imageURI = report.ExtractImageURI(destResult.files)
		destResult.tmpRoot = report.ExtractTmpRoot(destResult.files)
	default:
		if srcResult, destResult, err = diffScans(ctx, c, srcPath, destPath, srcIsArchive, destIsArchive, isImage); err != nil {
			return nil, err
		}
	}

	d := &malcontent.DiffReport{
		Added:    orderedmap.New[string, *malcontent.FileReport](),
		Removed:  orderedmap.New[string, *malcontent.FileReport](),
		Modified: orderedmap.New[string, *malcontent.FileReport](),
	}

	srcInfo, err := file.Stat(srcPath)
	if err != nil {
		return nil, err
	}

	destInfo, err := file.Stat(destPath)
	if err != nil {
		return nil, err
	}

	// When scanning two directories, compare the files in each directory
	// and employ add/delete for files that are not the same
	// When scanning two files, do a 1:1 comparison and
	// consider the source -> destination as a change rather than an add/delete
	// An image is scanned as the directory it is extracted to.
	shouldHandleDir := ((srcInfo.IsDir() && destInfo.IsDir()) || (srcIsArchive && destIsArchive)) || isReport
	archiveOrImage := (srcIsArchive && destIsArchive) || isImage

	if shouldHandleDir {
		handleDir(ctx, c, srcResult, destResult, d, archiveOrImage, isReport)
	} else {
		srcFile := selectPrimaryFile(srcResult.files)
		destFile := selectPrimaryFile(destResult.files)
		if srcFile != nil && destFile != nil {
			removed := formatReportKey(srcResult, srcFile, false)
			added := formatReportKey(destResult, destFile, false)
			fileDiff(ctx, c, srcFile, destFile, removed, added, d, srcResult, destResult, archiveOrImage, isReport, false)
		}
	}

	// Diffing stops early once ctx is canceled, leaving the report incomplete.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("diff canceled: %w", err)
	}

	return &malcontent.Report{Diff: d}, nil
}

// diffScans scans both sides of a diff at once. A failure of the source is
// reported even when the destination also fails, as when the source was
// scanned first, and it ends the destination scan.
func diffScans(ctx context.Context, c malcontent.Config, srcPath, destPath string, srcIsArchive, destIsArchive, isImage bool) (ScanResult, ScanResult, error) {
	ctx = diffScanContext(ctx, c)
	destCtx, cancelDest := context.WithCancel(ctx)
	defer cancelDest()

	var (
		dest    ScanResult
		destErr error
		wg      sync.WaitGroup
	)
	wg.Go(func() {
		dest, destErr = diffScan(destCtx, c, destPath, c.ScanPaths[1], destIsArchive, isImage)
	})
	src, err := diffScan(ctx, c, srcPath, c.ScanPaths[0], srcIsArchive, isImage)
	if err != nil {
		cancelDest()
		wg.Wait()
		return ScanResult{}, ScanResult{}, fmt.Errorf("source scan error: %w", err)
	}
	wg.Wait()
	if destErr != nil {
		return ScanResult{}, ScanResult{}, fmt.Errorf("destination scan error: %w", destErr)
	}
	return src, dest, nil
}

// diffScanContext returns ctx carrying what the two scans of a diff share: a
// result cache, so that content they have in common, such as the files a new
// version leaves unchanged, is scanned once, and the worker slots of one scan,
// so that together they use no more workers than one.
func diffScanContext(ctx context.Context, c malcontent.Config) context.Context {
	return withWorkerSlots(withResultCache(ctx), getMaxConcurrency(c.Concurrency))
}

// diffScan scans path, one side of a diff, keying its file reports by
// relPath. For an image, imageURI names the image and path is the directory
// it was extracted to; scanned paths have their symlinks resolved, so that
// directory is resolved too before it is trimmed from them.
func diffScan(ctx context.Context, c malcontent.Config, path, imageURI string, isArchive, isImage bool) (ScanResult, error) {
	frs, base, err := relFileReport(ctx, c, path, isArchive)
	if err != nil {
		return ScanResult{}, err
	}
	res := ScanResult{files: frs, base: base, isArchive: isArchive}
	if isImage {
		res.imageURI, res.tmpRoot = imageURI, resolvePath(path)
	}
	return res, nil
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
		entry    files.Entry
		srcPath  string
		destPath string
	}

	entries := make([]diffEntry, 0, len(result.E))
	for entry := range result.All() {
		var srcPath, destPath string
		if entry.Status != files.Added {
			srcPath = srcPaths[entry.Old]
		}
		if entry.Status != files.Removed {
			destPath = destPaths[entry.New]
		}
		entries = append(entries, diffEntry{entry, srcPath, destPath})
	}

	// Sort entries by path for deterministic output: the destination path, or
	// for a removed file, which has none, the source path.
	slices.SortFunc(entries, func(a, b diffEntry) int {
		return strings.Compare(cmp.Or(a.destPath, a.srcPath), cmp.Or(b.destPath, b.srcPath))
	})

	for _, e := range entries {
		switch e.entry.Status {
		case files.Unchanged, files.Updated:
			srcFr := srcFiles[e.srcPath]
			destFr := destFiles[e.destPath]
			rpath := formatReportKey(src, srcFr, isReport)
			apath := formatReportKey(dest, destFr, isReport)
			// Determine whether this is a move (Updated) vs change (Unchanged)
			isMoved := e.entry.Status == files.Updated
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
		// Extract just the file path after the first separator
		if _, after, ok := strings.Cut(path, "∴"); ok {
			return strings.TrimSpace(after)
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
	switch {
	case isReport:
		return report.FormatReportKey(fr.Path, res.tmpRoot, res.imageURI)
	case res.isArchive:
		return formatKey(res, archiveEntryPath(fr))
	default:
		return formatKey(res, CleanPath(fr.Path, res.tmpRoot))
	}
}

// fileDiff handles files that exist in both source and destination.
func fileDiff(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport, rpath, apath string, d *malcontent.DiffReport, src ScanResult, dest ScanResult, archiveOrImage, isReport, isMoved bool) {
	if ctx.Err() != nil {
		return
	}

	if fr.RiskScore < c.MinFileRisk && tr.RiskScore < c.MinFileRisk {
		clog.InfoContext(ctx, "diff does not meet min trigger level", slog.Any("path", tr.Path))
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
	slices.SortFunc(abs.Behaviors, func(a, b *malcontent.Behavior) int {
		return cmp.Compare(a.ID, b.ID)
	})

	if isReport {
		abs.Path = report.FormatReportKey(abs.Path, dest.tmpRoot, dest.imageURI)
		if isMoved {
			abs.PreviousPath = report.FormatReportKey(abs.PreviousPath, src.tmpRoot, src.imageURI)
		}
	} else if archiveOrImage {
		// The report keys already name each file by its path within the archive or image.
		abs.Path = apath
		if isMoved {
			abs.PreviousPath = rpath
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
	// The technique keeps any deeper components.
	parts := strings.SplitN(id, "/", 3)
	bc := behavior{objective: parts[0]}
	if len(parts) > 1 {
		bc.resource = parts[1]
	}
	if len(parts) > 2 {
		bc.technique = parts[2]
	}
	return bc
}

// extractBehaviors extracts unique components at the specified sensitivity level from behaviors.
func extractBehaviors(behaviors []*malcontent.Behavior, sensitivity int) map[string]struct{} {
	components := make(map[string]struct{})

	for _, b := range behaviors {
		if b == nil {
			continue
		}

		bc := parseBehaviorID(b.ID)

		switch sensitivity {
		case OBJECTIVE:
			if bc.objective != "" {
				components[bc.objective] = struct{}{}
			}
		case RESOURCE:
			if bc.objective != "" && bc.resource != "" {
				key := fmt.Sprintf("%s/%s", bc.objective, bc.resource)
				components[key] = struct{}{}
			} else if bc.objective != "" {
				components[bc.objective] = struct{}{}
			}
		case TECHNIQUE:
			if b.ID != "" {
				components[b.ID] = struct{}{}
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
		if _, ok := sb[bc]; !ok {
			return true
		}
	}

	for bc := range sb {
		if _, ok := db[bc]; !ok {
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
			clog.InfoContext(ctx, "dropping result because no technique-level changes detected",
				slog.Any("paths", fmt.Sprintf("%s -> %s", fr.Path, tr.Path)))
			return true
		}
		return false
	case c.Sensitivity == RESOURCE:
		if !behaviorsChanged(fr, tr, RESOURCE) {
			clog.InfoContext(ctx, "dropping result because no resource-level changes detected",
				slog.Any("paths", fmt.Sprintf("%s -> %s", fr.Path, tr.Path)))
			return true
		}
		return false
	case c.Sensitivity == OBJECTIVE:
		if !behaviorsChanged(fr, tr, OBJECTIVE) {
			clog.InfoContext(ctx, "dropping result because no objective-level changes detected",
				slog.Any("paths", fmt.Sprintf("%s -> %s", fr.Path, tr.Path)))
			return true
		}
		return false
	case change && equalRisk:
		clog.InfoContext(ctx, "dropping result because diff scores were the same",
			slog.Any("paths", fmt.Sprintf("%s (%d) %s (%d)", fr.Path, fr.RiskScore, tr.Path, tr.RiskScore)))
		return true
	case c.FileRiskIncrease && lessRisk:
		clog.InfoContext(ctx, "dropping result because old score was the same or higher than the new score",
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
