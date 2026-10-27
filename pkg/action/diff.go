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
)

type ScanResult struct {
	files map[string]*malcontent.FileReport
	base  string
	// tmpRoot is the directory an image was extracted to. imageURI names the
	// image or, for a report, the archive or image that holds every entry.
	tmpRoot  string
	imageURI string
	// isArchive is set when the scan path is itself an archive, whose entries
	// are keyed by their path within it.
	isArchive bool
}

// scanRoot is where one side of a diff was scanned from. It keys each file
// by its path below the root, so that the files of the two sides pair.
type scanRoot struct {
	// base prefixes report keys: the absolute scan path, spelled as display
	// paths spell it.
	base string
	// root is the scan path, or the directory holding a scanned file, with
	// symlinks resolved, and resolved is root through resolvePath. An archive
	// scan has neither, since its entries are keyed by their path within it.
	root, resolved string
	isArchive      bool
}

// newScanRoot returns the root of a scan of from, an archive when isArchive is set.
func newScanRoot(from string, isArchive bool) (scanRoot, error) {
	base, err := filepath.Abs(from)
	if err != nil {
		return scanRoot{}, err
	}
	r := scanRoot{base: report.DisplayPath(base, nil), isArchive: isArchive}
	if isArchive {
		return r, nil
	}

	info, err := file.Stat(from)
	if err != nil {
		return scanRoot{}, err
	}
	// Remove any file name so a single file is keyed by its name: keying
	// both sides as "." would pair completely unrelated files and paths.
	root := from
	if !info.IsDir() {
		root = filepath.Dir(from)
	}
	if r.root, err = filepath.EvalSymlinks(root); err != nil {
		return scanRoot{}, err
	}
	r.resolved = resolvePath(r.root)
	return r, nil
}

// rel returns the key that pairs fr with its counterpart in the other scan.
// Entries of an archive scan are keyed by their path within the archive;
// other files by their path below the scan root.
func (r scanRoot) rel(fr *malcontent.FileReport) (string, error) {
	if r.isArchive {
		return archiveEntryPath(fr), nil
	}
	if pathWithin(fr.Path, r.root) {
		return filepath.Rel(r.root, fr.Path)
	}
	// The path is spelled through a symlinked directory (e.g. macOS' /tmp -> /private/tmp),
	// so resolve both sides the same way before comparing them.
	return filepath.Rel(r.resolved, resolvePath(fr.Path))
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

// selectPrimaryFile selects a single file from a map of file reports in a deterministic way:
// the first, in sorted order, that is not a UPX backup. e.g., when a UPX-packed file is
// scanned, it produces the decompressed file and preserves the original file.
func selectPrimaryFile(f map[string]*malcontent.FileReport) *malcontent.FileReport {
	if len(f) == 0 {
		return nil
	}

	keys := slices.Sorted(maps.Keys(f))
	if i := slices.IndexFunc(keys, func(k string) bool { return isPrimaryFile(k, f) }); i >= 0 {
		return f[keys[i]]
	}
	return f[keys[0]]
}

// isPrimaryFile reports whether the file f holds under key is named and is not a UPX backup.
func isPrimaryFile(key string, f map[string]*malcontent.FileReport) bool {
	return key != "" && !isUPXBackup(key, f)
}

// primaryFiles returns how many files of f are primary files.
func primaryFiles(f map[string]*malcontent.FileReport) int {
	n := 0
	for k := range f {
		if isPrimaryFile(k, f) {
			n++
		}
	}
	return n
}

// isUPXBackup reports whether path names the backup that `upx -d -k` keeps of
// a file in f. UPX names it by replacing the last character of a name with an
// extension by "~", or by appending ".~" to a name without one.
func isUPXBackup(path string, f map[string]*malcontent.FileReport) bool {
	stem, ok := strings.CutSuffix(path, "~")
	if !ok || stem == "" {
		return false
	}
	// "app" and "app." both back up to "app.~".
	if orig, ok := strings.CutSuffix(stem, "."); ok {
		if _, exists := f[orig]; exists {
			return true
		}
		if _, exists := f[stem]; exists {
			return true
		}
	}
	// "app.exe" backs up to "app.ex~", so the original differs in its last byte.
	if !strings.Contains(stem[strings.LastIndexByte(stem, '/')+1:], ".") {
		return false
	}
	orig := []byte(stem + "~")
	for c := range 256 {
		if c == '~' {
			continue
		}
		orig[len(orig)-1] = byte(c)
		if _, exists := f[string(orig)]; exists {
			return true
		}
	}
	return false
}

// relFileReport scans fromPath and keys each file report by its path below
// the scan root. isArchive reports whether fromPath is itself an archive.
func relFileReport(ctx context.Context, c malcontent.Config, fromPath string, isArchive bool) (map[string]*malcontent.FileReport, string, error) {
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}

	// Display paths are trimmed once each file is keyed, since a trimmed path
	// no longer names the file below the scan root.
	fromConfig := c
	fromConfig.Renderer = nil
	fromConfig.TrimPrefixes = nil
	fromConfig.ScanPaths = []string{fromPath}
	fromReport, err := recursiveScan(ctx, fromConfig)
	if err != nil {
		return nil, "", err
	}
	root, err := newScanRoot(fromPath, isArchive)
	if err != nil {
		return nil, "", err
	}

	fromRelPath := map[string]*malcontent.FileReport{}
	var rangeErr error
	fromReport.Files.Range(func(key string, fr *malcontent.FileReport) bool {
		if ctx.Err() != nil {
			return false
		}
		if key == "" || fr == nil || fr.Skipped != "" {
			return true
		}

		rel, err := root.rel(fr)
		if err != nil {
			rangeErr = err
			return false
		}
		// A trim prefix equal to a scanned path leaves no name to report.
		if fr.Path = report.DisplayPath(fr.Path, c.TrimPrefixes); fr.Path == "" {
			return true
		}

		fr.PreviousRelPath = rel
		fromRelPath[rel] = fr
		return true
	})

	if rangeErr != nil {
		return nil, "", rangeErr
	}
	// Range stops early once ctx is canceled, leaving the map incomplete.
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	return fromRelPath, root.base, nil
}

func Diff(ctx context.Context, c malcontent.Config, _ *clog.Logger) (*malcontent.Report, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	ctx = malcontent.ContextWithConfig(ctx, &c)

	if len(c.ScanPaths) != 2 {
		return nil, fmt.Errorf("diff mode requires 2 paths, you passed in %d path(s)", len(c.ScanPaths))
	}
	if c.Sensitivity < 0 || c.Sensitivity > ALL {
		return nil, fmt.Errorf("diff sensitivity %d is out of range: want %d through %d, or 0 for the default", c.Sensitivity, CHANGE, ALL)
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

		// Extract the target and temp root from the report's file paths
		srcResult.imageURI = reportTarget(srcResult.files)
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

		// Extract the target and temp root from the report's file paths
		destResult.imageURI = reportTarget(destResult.files)
		destResult.tmpRoot = report.ExtractTmpRoot(destResult.files)
	default:
		if srcResult, destResult, err = diffScans(ctx, c, srcPath, destPath, srcIsArchive, destIsArchive, isImage); err != nil {
			return nil, err
		}
	}

	d := &malcontent.DiffReport{
		Added:    new(malcontent.OrderedFileReports),
		Removed:  new(malcontent.OrderedFileReports),
		Modified: new(malcontent.OrderedFileReports),
	}

	srcInfo, err := file.Stat(srcPath)
	if err != nil {
		return nil, err
	}

	destInfo, err := file.Stat(destPath)
	if err != nil {
		return nil, err
	}

	// When either side is a tree, compare the files in each tree
	// and employ add/delete for files that are not the same
	// When diffing two files, do a 1:1 comparison and
	// consider the source -> destination as a change rather than an add/delete
	// An image is scanned as the directory it is extracted to.
	archiveOrImage := (srcIsArchive && destIsArchive) || isImage

	if diffTrees(srcInfo.IsDir(), destInfo.IsDir(), srcIsArchive, destIsArchive, isReport, srcResult, destResult) {
		// A canceled diff is reported below.
		if err := handleDir(ctx, c, srcResult, destResult, d, archiveOrImage, isReport); err != nil && ctx.Err() == nil {
			return nil, err
		}
	} else {
		srcFile := selectPrimaryFile(srcResult.files)
		destFile := selectPrimaryFile(destResult.files)
		if srcFile != nil && destFile != nil {
			removed := formatReportKey(srcResult, srcFile, isReport)
			added := formatReportKey(destResult, destFile, isReport)
			fileDiff(ctx, c, srcFile, destFile, removed, added, d, srcResult, destResult, archiveOrImage, isReport, false)
		}
	}

	// Diffing stops early once ctx is canceled, leaving the report incomplete.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("diff canceled: %w", err)
	}

	return &malcontent.Report{Diff: d}, nil
}

// diffTrees reports whether a diff reconciles the files of its two sides by
// path, rather than comparing one file with the other. A directory is a tree,
// as is an archive diffed against another archive. An archive diffed against
// a file, and a report, are trees unless they hold a single primary file.
func diffTrees(srcIsDir, destIsDir, srcIsArchive, destIsArchive, isReport bool, src, dest ScanResult) bool {
	switch {
	case isReport:
		return primaryFiles(src.files) != 1 || primaryFiles(dest.files) != 1
	case srcIsDir || destIsDir, srcIsArchive && destIsArchive:
		return true
	case srcIsArchive:
		return primaryFiles(src.files) != 1
	case destIsArchive:
		return primaryFiles(dest.files) != 1
	default:
		return false
	}
}

// reportTarget returns the archive or image that holds every entry of a
// report: the "<target> ∴ " prefix that the path of each entry shares. An
// entry without findings may be spelled by its temporary path instead, so it
// does not count against a target. It returns "" when the entries lie in more
// than one target, or when an entry with findings lies outside any.
func reportTarget(frs map[string]*malcontent.FileReport) string {
	target := ""
	for _, fr := range frs {
		outer, _, ok := strings.Cut(fr.Path, " ∴ ")
		switch {
		case !ok && len(fr.Behaviors) == 0:
			continue
		case !ok, target != "" && outer != target:
			return ""
		}
		target = outer
	}
	return target
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
// it was extracted to; it is trimmed from the display paths of the files
// scanned there, so it is resolved and then spelled as they are.
func diffScan(ctx context.Context, c malcontent.Config, path, imageURI string, isArchive, isImage bool) (ScanResult, error) {
	frs, base, err := relFileReport(ctx, c, path, isArchive)
	if err != nil {
		return ScanResult{}, err
	}
	res := ScanResult{files: frs, base: base, isArchive: isArchive}
	if isImage {
		res.imageURI, res.tmpRoot = imageURI, report.DisplayPath(resolvePath(path), nil)
	}
	return res, nil
}

// handleDir uses diff for O(n+m) file reconciliation with identity-based matching.
// This enables detection of version updates (e.g., lib.so.1 -> lib.so.2) in addition
// to exact path matches, and scales efficiently to millions of files.
// It returns an error when two files of one side clean to the same key.
func handleDir(ctx context.Context, c malcontent.Config, src, dest ScanResult, d *malcontent.DiffReport, archiveOrImage, isReport bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Build file maps keyed by relative path (i.e., the path within an image/archive, not the temp dir)
	// This ensures files with the same logical path match regardless of temporary directory.
	srcFiles, srcPaths, err := reconcileKeys(src, isReport)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	destFiles, destPaths, err := reconcileKeys(dest, isReport)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}

	// Fast O(n+m) reconciliation with identity-based matching
	result := files.Diff(alignRoots(srcPaths, destPaths, srcFiles, destFiles))

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
			// A move (Updated), or a pair from trees scanned from different
			// roots, records where the file was; a change (Unchanged) does not.
			isMoved := e.entry.Status == files.Updated || e.srcPath != e.destPath
			fileDiff(ctx, c, srcFr, destFr, rpath, apath, d, src, dest, archiveOrImage, isReport, isMoved)

		// A file without a counterpart is left out below the minimum file
		// risk, as fileDiff leaves out a pair whose sides both fall below it.
		case files.Removed:
			if srcFr := srcFiles[e.srcPath]; srcFr.RiskScore >= c.MinFileRisk {
				d.Removed.Set(formatReportKey(src, srcFr, isReport), srcFr)
			}

		case files.Added:
			if destFr := destFiles[e.destPath]; destFr.RiskScore >= c.MinFileRisk {
				d.Added.Set(formatReportKey(dest, destFr, isReport), destFr)
			}
		}
	}
	return nil
}

// reconcileKeys returns the files of res keyed for reconciliation, and the keys in
// sorted order. Unnamed entries and UPX backups are left out. Files whose paths
// clean to the same key make the diff ambiguous, since pairing either one would
// hide the other, so reconcileKeys returns an error naming them.
func reconcileKeys(res ScanResult, isReport bool) (map[string]*malcontent.FileReport, []string, error) {
	keyed := make(map[string]*malcontent.FileReport, len(res.files))
	keys := make([]string, 0, len(res.files))
	shared := map[string][]string{}
	for rel, fr := range res.files {
		if !isPrimaryFile(rel, res.files) {
			continue
		}
		key := extractPath(rel, fr, res, isReport)
		if key == "" {
			continue
		}
		if prev, ok := keyed[key]; ok {
			if _, seen := shared[key]; !seen {
				shared[key] = []string{prev.Path}
			}
			shared[key] = append(shared[key], fr.Path)
			continue
		}
		keyed[key] = fr
		keys = append(keys, key)
	}
	if len(shared) > 0 {
		key := slices.Min(slices.Collect(maps.Keys(shared)))
		paths := slices.Sorted(slices.Values(shared[key]))
		return nil, nil, fmt.Errorf("ambiguous diff: %s share the key %q", strings.Join(paths, " and "), key)
	}
	slices.Sort(keys)
	return keyed, keys, nil
}

// extractPath returns the key that reconciles fr, which its scan keyed by rel.
// A report entry is keyed by its path without the target that holds every
// entry, or the temporary directory it was extracted to. Other files are keyed
// by rel with a leading slash, so that the paths below a directory pair with
// the paths within an archive.
func extractPath(rel string, fr *malcontent.FileReport, res ScanResult, isReport bool) string {
	if !isReport {
		return "/" + strings.TrimPrefix(filepath.ToSlash(rel), "/")
	}
	if res.imageURI != "" {
		if path, ok := strings.CutPrefix(fr.Path, res.imageURI+" ∴ "); ok {
			return path
		}
	}
	return report.CleanReportPath(fr.Path, res.tmpRoot, "")
}

// alignRoots returns the keys of two trees rewritten so that trees scanned from
// different roots, such as two report directories or the versioned top-level
// directories of two releases, pair by their paths below those roots. Each
// side's root is the deepest directory that holds its keys, or an ancestor of
// it, chosen to pair the most files. Trees that share a key were scanned from
// the same root and keep their keys, as do trees that no choice of roots pairs.
func alignRoots(srcKeys, destKeys []string, srcFiles, destFiles map[string]*malcontent.FileReport) ([]string, []string) {
	if len(srcKeys) == 0 || len(destKeys) == 0 || sharesKey(srcKeys, destKeys, srcFiles, destFiles) {
		return srcKeys, destKeys
	}
	srcDir, destDir := commonDir(srcKeys), commonDir(destKeys)
	srcRel, destRel := trimKeys(srcKeys, len(srcDir)), trimKeys(destKeys, len(destDir))
	srcSet, destSet := keySet(srcRel), keySet(destRel)

	// A root above a side's deepest directory leaves the directories between
	// them on each key. The two sides pair when the directories one side keeps
	// extend those of the other, and the other side's keys gain the extension.
	type shift struct {
		dirs  string
		onSrc bool // whether the source keys gain dirs, rather than the destination keys
	}
	var shifts []shift
	for _, st := range dirTails(srcDir) {
		for _, dt := range dirTails(destDir) {
			if dirs, ok := strings.CutPrefix(dt, st); ok {
				shifts = append(shifts, shift{dirs: dirs})
			} else if dirs, ok := strings.CutPrefix(st, dt); ok {
				shifts = append(shifts, shift{dirs: dirs, onSrc: true})
			}
		}
	}
	// Ties go to the shortest extension, so the deepest roots are preferred.
	slices.SortFunc(shifts, func(a, b shift) int {
		return cmp.Or(cmp.Compare(len(a.dirs), len(b.dirs)), strings.Compare(a.dirs, b.dirs), cmp.Compare(btoi(a.onSrc), btoi(b.onSrc)))
	})
	shifts = slices.Compact(shifts)

	best, bestPairs := shift{}, 0
	for _, s := range shifts {
		// Keys that gain no directories pair alike from either side.
		keys, other := srcRel, destSet
		if s.onSrc || s.dirs == "" && len(destRel) < len(srcRel) {
			keys, other = destRel, srcSet
		}
		if n := shiftPairs(keys, s.dirs, other); n > bestPairs {
			best, bestPairs = s, n
		}
	}
	switch {
	case bestPairs == 0:
		return srcKeys, destKeys
	case best.onSrc:
		return prefixKeys(srcRel, best.dirs), destRel
	default:
		return srcRel, prefixKeys(destRel, best.dirs)
	}
}

// sharesKey reports whether the two sides of a diff share a key, looking the
// keys of the smaller side up among the files of the other.
func sharesKey(srcKeys, destKeys []string, srcFiles, destFiles map[string]*malcontent.FileReport) bool {
	keys, other := srcKeys, destFiles
	if len(destKeys) < len(srcKeys) {
		keys, other = destKeys, srcFiles
	}
	return slices.ContainsFunc(keys, func(k string) bool {
		_, ok := other[k]
		return ok
	})
}

// shiftPairs returns how many keys pair with the other side once its keys gain
// dirs: the keys that start with dirs and whose remainder the other side holds.
func shiftPairs(keys []string, dirs string, other map[string]struct{}) int {
	n := 0
	for _, k := range keys {
		if rest, ok := strings.CutPrefix(k, dirs); ok {
			if _, found := other[rest]; found {
				n++
			}
		}
	}
	return n
}

// commonDir returns the deepest directory, ending in a slash, that holds every
// key, judging an archive member by the archive that holds it.
func commonDir(keys []string) string {
	dir := ""
	for i, k := range keys {
		outer, _, _ := strings.Cut(k, " ∴ ")
		if i == 0 {
			dir = outer[:strings.LastIndexByte(outer, '/')+1]
			continue
		}
		for !strings.HasPrefix(outer, dir) {
			dir = dir[:strings.LastIndexByte(dir[:len(dir)-1], '/')+1]
		}
	}
	return dir
}

// dirTails returns the trailing directories of dir, a path ending in a slash,
// shortest first: "/a/b/" yields "", "b/", and "a/b/".
func dirTails(dir string) []string {
	tails := []string{""}
	for i := len(dir) - 2; i >= 0; i-- {
		if dir[i] == '/' {
			tails = append(tails, dir[i+1:])
		}
	}
	return tails
}

// trimKeys returns keys without their first n bytes.
func trimKeys(keys []string, n int) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k[n:]
	}
	return out
}

// prefixKeys returns keys with dirs before each.
func prefixKeys(keys []string, dirs string) []string {
	if dirs == "" {
		return keys
	}
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = dirs + k
	}
	return out
}

// keySet returns keys as a set.
func keySet(keys []string) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[k] = struct{}{}
	}
	return set
}

// btoi returns 1 for true and 0 for false.
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
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
		PreviousRiskLevel: riskLevel(fr),

		RiskScore: tr.RiskScore,
		RiskLevel: riskLevel(tr),
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

// riskLevel returns the risk level of fr. A file without findings carries
// none, so its level is that of its score.
func riskLevel(fr *malcontent.FileReport) string {
	return cmp.Or(fr.RiskLevel, report.RiskLevels[fr.RiskScore])
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
// 0 leaves the sensitivity unset, which is the same as 5. --file-risk-change and
// --file-risk-increase apply at every level.
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
// The risk flags apply at every sensitivity, including the CLI's default of 5.
func filterDiff(ctx context.Context, c malcontent.Config, fr, tr *malcontent.FileReport) bool {
	if ctx.Err() != nil {
		return false
	}

	switch {
	case (c.FileRiskChange || c.Sensitivity == CHANGE) && fr.RiskScore == tr.RiskScore:
		clog.InfoContext(ctx, "dropping result because diff scores were the same",
			slog.Any("paths", fmt.Sprintf("%s (%d) %s (%d)", fr.Path, fr.RiskScore, tr.Path, tr.RiskScore)))
		return true
	case c.FileRiskIncrease && fr.RiskScore >= tr.RiskScore:
		clog.InfoContext(ctx, "dropping result because old score was the same or higher than the new score",
			slog.Any("paths", fmt.Sprintf("%s (%d) %s (%d)", fr.Path, fr.RiskScore, tr.Path, tr.RiskScore)))
		return true
	}

	var level string
	switch c.Sensitivity {
	case OBJECTIVE:
		level = "objective"
	case RESOURCE:
		level = "resource"
	case TECHNIQUE:
		level = "technique"
	default:
		return false
	}
	if behaviorsChanged(fr, tr, c.Sensitivity) {
		return false
	}
	clog.InfoContext(ctx, "dropping result because no "+level+"-level changes detected",
		slog.Any("paths", fmt.Sprintf("%s -> %s", fr.Path, tr.Path)))
	return true
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
